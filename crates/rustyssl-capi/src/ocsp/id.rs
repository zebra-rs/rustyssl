//! Certificate IDs (`ocsp_lib.c`): the issuer's name and key hashes and the serial number
//! that name a certificate, and comparing them.

use core::ffi::c_int;
use core::ptr;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_INTEGER, ERR_LIB_OCSP, EVP_MAX_MD_SIZE, EVP_MD, NID_undef, OCSP_CERTID,
    OCSP_R_DIGEST_ERR, OCSP_R_UNKNOWN_NID, V_ASN1_NULL, X509, X509_NAME,
};

use super::asn::{CertId, OCSP_CERTID_free, OCSP_CERTID_new, of};
use crate::asn1::integer::ASN1_INTEGER_cmp;
use crate::asn1::string::{ASN1_OCTET_STRING_cmp, ASN1_OCTET_STRING_set, ASN1_STRING_copy};
use crate::asn1::tpl::items::ASN1_TYPE_new;
use crate::err;
use crate::evp::digest::EVP_MD_get_type;
use crate::evp::legacy_md::EVP_sha1;
use crate::evp::md_ctx::EVP_Digest;
use crate::ffi::ffi_export;
use crate::objects::{ASN1_OBJECT_free, OBJ_cmp, OBJ_nid2obj};
use crate::x509::cert::{
    X509_get_issuer_name, X509_get_subject_name, X509_get0_pubkey_bitstr, X509_get0_serialNumber,
};
use crate::x509::name::X509_NAME_digest;

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_OCSP, reason, f);
}

ffi_export! {
    /// The CertID of `subject` (or, with no subject, of `issuer`'s name and no serial number),
    /// hashed with `dgst` (SHA-1 for NULL). NULL on failure.
    ///
    /// # Safety
    /// `dgst` and `subject` are NULL or live; `issuer` a live certificate.
    pub unsafe extern "C" fn OCSP_cert_to_id(dgst: *const EVP_MD, subject: *const X509, issuer: *const X509) -> *mut OCSP_CERTID
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: no preconditions.
        let dgst = if dgst.is_null() { unsafe { EVP_sha1() } } else { dgst };
        let (iname, serial) = if subject.is_null() {
            // SAFETY: the caller's issuer.
            (unsafe { X509_get_subject_name(issuer) }, ptr::null())
        } else {
            // SAFETY: the caller's subject.
            let n = unsafe { X509_get_issuer_name(subject) };
            // SAFETY: as above.
            (n, unsafe { X509_get0_serialNumber(subject) })
        };
        // SAFETY: the caller's issuer.
        let ikey = unsafe { X509_get0_pubkey_bitstr(issuer) };
        // SAFETY: the digest; the name, key, and serial number.
        unsafe { OCSP_cert_id_new(dgst, iname, ikey, serial) }
    }
}

ffi_export! {
    /// A CertID of the issuer's name and key (its BIT STRING's octets) hashed with `dgst`, and
    /// the serial number (if any). NULL on failure.
    ///
    /// # Safety
    /// `dgst`, `issuer_name`, and `issuer_key` are live; `serial_number_` NULL or live.
    pub unsafe extern "C" fn OCSP_cert_id_new(dgst: *const EVP_MD, issuer_name: *const X509_NAME, issuer_key: *const ASN1_BIT_STRING, serial_number_: *const ASN1_INTEGER) -> *mut OCSP_CERTID
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        const F: &str = "OCSP_cert_id_new";
        // SAFETY: no preconditions.
        let cid = unsafe { OCSP_CERTID_new() };
        let ok = 'err: {
            // SAFETY: the new CertID, or NULL.
            let Some(c) = (unsafe { of::<CertId, _>(cid) }) else { break 'err false };
            let alg = &mut c.hash_algorithm;
            // SAFETY: its own object.
            unsafe { ASN1_OBJECT_free(alg.algorithm) };
            alg.algorithm = ptr::null_mut();
            // SAFETY: the caller's digest.
            let nid = unsafe { EVP_MD_get_type(dgst) };
            if nid == NID_undef {
                raise(OCSP_R_UNKNOWN_NID, F);
                break 'err false;
            }
            // SAFETY: any NID.
            alg.algorithm = unsafe { OBJ_nid2obj(nid) };
            if alg.algorithm.is_null() {
                break 'err false;
            }
            // SAFETY: no preconditions.
            alg.parameter = unsafe { ASN1_TYPE_new() };
            // SAFETY: the new parameter, or NULL.
            let Some(p) = (unsafe { alg.parameter.as_mut() }) else { break 'err false };
            p.type_ = V_ASN1_NULL;
            let mut md = [0u8; EVP_MAX_MD_SIZE as usize];
            let mut n: core::ffi::c_uint = 0;
            // SAFETY: the caller's name and digest; room for it.
            if unsafe { X509_NAME_digest(issuer_name, dgst, md.as_mut_ptr(), &mut n) } == 0 {
                raise(OCSP_R_DIGEST_ERR, F);
                break 'err false;
            }
            let Ok(len) = c_int::try_from(n) else { break 'err false };
            // SAFETY: the CertID's string; the hash.
            if unsafe { ASN1_OCTET_STRING_set(&mut c.issuer_name_hash, md.as_ptr(), len) } == 0 {
                break 'err false;
            }
            // The issuer key's hash, without its tag and length.
            // SAFETY: the caller's key.
            let k = unsafe { &*issuer_key };
            let Ok(klen) = usize::try_from(k.length) else { break 'err false };
            // SAFETY: the key's octets; room for the hash; the digest.
            if unsafe { EVP_Digest(k.data.cast(), klen, md.as_mut_ptr(), &mut n, dgst, ptr::null_mut()) } == 0 {
                break 'err false;
            }
            let Ok(len) = c_int::try_from(n) else { break 'err false };
            // SAFETY: as above.
            if unsafe { ASN1_OCTET_STRING_set(&mut c.issuer_key_hash, md.as_ptr(), len) } == 0 {
                break 'err false;
            }
            // SAFETY: the CertID's serial number; the caller's.
            if !serial_number_.is_null() && unsafe { ASN1_STRING_copy(&mut c.serial_number, serial_number_) } == 0 {
                break 'err false;
            }
            true
        };
        if ok {
            return cid;
        }
        // SAFETY: the CertID made here, or NULL.
        unsafe { OCSP_CERTID_free(cid) };
        ptr::null_mut()
    }
}

ffi_export! {
    /// Compares two CertIDs' hash algorithms and issuer hashes: 0 if the same.
    ///
    /// # Safety
    /// `a` and `b` are live CertIDs.
    pub unsafe extern "C" fn OCSP_id_issuer_cmp(a: *const OCSP_CERTID, b: *const OCSP_CERTID) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let (Some(a), Some(b)) = (unsafe { of::<CertId, _>(a) }, unsafe { of::<CertId, _>(b) }) else { return -1 };
        // SAFETY: their algorithms' objects.
        let ret = unsafe { OBJ_cmp(a.hash_algorithm.algorithm, b.hash_algorithm.algorithm) };
        if ret != 0 {
            return ret;
        }
        // SAFETY: their hashes.
        let ret = unsafe { ASN1_OCTET_STRING_cmp(&a.issuer_name_hash, &b.issuer_name_hash) };
        if ret != 0 {
            return ret;
        }
        // SAFETY: as above.
        unsafe { ASN1_OCTET_STRING_cmp(&a.issuer_key_hash, &b.issuer_key_hash) }
    }
}

ffi_export! {
    /// Compares two CertIDs: 0 if the same.
    ///
    /// # Safety
    /// `a` and `b` are live CertIDs.
    pub unsafe extern "C" fn OCSP_id_cmp(a: *const OCSP_CERTID, b: *const OCSP_CERTID) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let ret = unsafe { OCSP_id_issuer_cmp(a, b) };
        if ret != 0 {
            return ret;
        }
        // SAFETY: as above.
        let (Some(a), Some(b)) = (unsafe { of::<CertId, _>(a) }, unsafe { of::<CertId, _>(b) }) else { return -1 };
        // SAFETY: their serial numbers.
        unsafe { ASN1_INTEGER_cmp(&a.serial_number, &b.serial_number) }
    }
}
