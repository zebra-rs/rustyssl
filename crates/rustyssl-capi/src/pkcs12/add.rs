//! Packing safe bags into PKCS#7 contents and back (`p12_add.c`): SafeContents as Data or
//! as password-encrypted EncryptedData, shrouded keys, and the authenticated safe.
//!
//! As OpenSSL does since CVE-2024-0727, a content without its data fails rather than being
//! read.

use core::ffi::{c_char, c_int, c_uchar};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PKCS12, ERR_R_ASN1_LIB, NID_pkcs7_data, NID_pkcs7_encrypted, OSSL_LIB_CTX, PKCS7,
    PKCS8_PRIV_KEY_INFO, PKCS12, PKCS12_R_CANT_PACK_STRUCTURE, PKCS12_R_CONTENT_TYPE_NOT_DATA,
    PKCS12_R_DECODE_ERROR, PKCS12_R_ENCRYPT_ERROR, PKCS12_R_ERROR_SETTING_ENCRYPTED_DATA_TYPE,
    PKCS12_SAFEBAG, stack_st_PKCS7, stack_st_PKCS12_SAFEBAG,
};

use super::asn::{PKCS12_AUTHSAFES_it, PKCS12_SAFEBAGS_it, bag_of, pfx_of};
use super::bags::pbe_cipher;
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new};
use crate::asn1::tpl::items::X509_ALGOR_free;
use crate::asn1::tpl::util::{ASN1_item_pack, ASN1_item_unpack_ex};
use crate::err;
use crate::evp::cipher::EVP_CIPHER_free;
use crate::ffi::ffi_export;
use crate::objects::{OBJ_nid2obj, OBJ_obj2nid};
use crate::pkcs7::{PKCS7_free, PKCS7_new, PKCS7_new_ex, PKCS7_set_type, resolve_libctx};
use crate::pkcs8_crypt::{
    PKCS8_decrypt_ex, PKCS12_item_decrypt_d2i_ex, PKCS12_item_i2d_encrypt_ex,
};
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value};
use crate::x509::cert::set0_libctx;
use crate::x509::pbe::{PKCS5_pbe_set_ex, PKCS5_pbe2_set_iv_ex};

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_PKCS12, reason, f);
}

/// The content type's NID.
fn type_nid(p7: &PKCS7) -> c_int {
    // SAFETY: its object, or NULL.
    unsafe { OBJ_obj2nid(p7.type_) }
}

ffi_export! {
    /// The bags as the OCTET STRING of a new PKCS#7 Data. NULL on failure.
    ///
    /// # Safety
    /// `sk` is a live list of safe bags.
    pub unsafe extern "C" fn PKCS12_pack_p7data(sk: *mut stack_st_PKCS12_SAFEBAG) -> *mut PKCS7
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        const F: &str = "PKCS12_pack_p7data";
        // SAFETY: no preconditions.
        let p7 = unsafe { PKCS7_new() };
        // SAFETY: the new object, or NULL.
        let Some(p) = (unsafe { p7.as_mut() }) else {
            raise(ERR_R_ASN1_LIB, F);
            return ptr::null_mut();
        };
        // SAFETY: a built-in NID.
        p.type_ = unsafe { OBJ_nid2obj(NID_pkcs7_data) };
        // SAFETY: no preconditions.
        p.d.data = unsafe { ASN1_OCTET_STRING_new() };
        // SAFETY: the content of its type.
        if unsafe { p.d.data }.is_null() {
            raise(ERR_R_ASN1_LIB, F);
            // SAFETY: the object made here.
            unsafe { PKCS7_free(p7) };
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let it = unsafe { PKCS12_SAFEBAGS_it() };
        // SAFETY: the caller's bags; the content's slot.
        if unsafe { ASN1_item_pack(sk.cast(), it, (&raw mut p.d.data).cast()) }.is_null() {
            raise(PKCS12_R_CANT_PACK_STRUCTURE, F);
            // SAFETY: as above.
            unsafe { PKCS7_free(p7) };
            return ptr::null_mut();
        }
        p7
    }
}

ffi_export! {
    /// The bags of a PKCS#7 Data, or NULL.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object.
    pub unsafe extern "C" fn PKCS12_unpack_p7data(p7: *mut PKCS7) -> *mut stack_st_PKCS12_SAFEBAG
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        const F: &str = "PKCS12_unpack_p7data";
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7.as_ref() }) else { return ptr::null_mut() };
        if type_nid(p) != NID_pkcs7_data {
            raise(PKCS12_R_CONTENT_TYPE_NOT_DATA, F);
            return ptr::null_mut();
        }
        // SAFETY: the content of its type.
        let data = unsafe { p.d.data };
        if data.is_null() {
            raise(PKCS12_R_DECODE_ERROR, F);
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let it = unsafe { PKCS12_SAFEBAGS_it() };
        // SAFETY: the content's string; the object's context and properties.
        unsafe { ASN1_item_unpack_ex(data, it, p.ctx.libctx, p.ctx.propq) }.cast()
    }
}

ffi_export! {
    /// The bags, encrypted with the password, as a new PKCS#7 EncryptedData (by PBES2 with
    /// `pbe_nid` a cipher, else the PKCS#12 PBE `pbe_nid`). NULL on failure.
    ///
    /// # Safety
    /// `pass` holds `passlen` octets (a C string if -1); `salt` NULL or `saltlen` octets; `bags`
    /// a live list; `ctx` NULL or live; `propq` NULL or a C string.
    pub unsafe extern "C" fn PKCS12_pack_p7encdata_ex(pbe_nid: c_int, pass: *const c_char, passlen: c_int, salt: *mut c_uchar, saltlen: c_int, iter: c_int, bags: *mut stack_st_PKCS12_SAFEBAG, ctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut PKCS7
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        const F: &str = "PKCS12_pack_p7encdata_ex";
        // SAFETY: the caller's guarantee.
        let p7 = unsafe { PKCS7_new_ex(ctx, propq) };
        if p7.is_null() {
            raise(ERR_R_ASN1_LIB, F);
            return ptr::null_mut();
        }
        let mut fetched = ptr::null_mut();
        let ok = 'err: {
            // SAFETY: the new object.
            if unsafe { PKCS7_set_type(p7, NID_pkcs7_encrypted) } == 0 {
                raise(PKCS12_R_ERROR_SETTING_ENCRYPTED_DATA_TYPE, F);
                break 'err false;
            }
            // SAFETY: as above.
            let (cipher, f) = unsafe { pbe_cipher(pbe_nid, ctx, propq) };
            fetched = f;
            let pbe = if cipher.is_null() {
                // SAFETY: the caller's salt, or NULL.
                unsafe { PKCS5_pbe_set_ex(pbe_nid, iter, salt, saltlen, ctx) }
            } else {
                // SAFETY: as above; a live cipher; no PRF given.
                unsafe { PKCS5_pbe2_set_iv_ex(cipher, iter, salt, saltlen, ptr::null_mut(), -1, ctx) }
            };
            if pbe.is_null() {
                raise(ERR_R_ASN1_LIB, F);
                break 'err false;
            }
            // SAFETY: the object made here.
            let pp = unsafe { &*p7 };
            // SAFETY: its content, now EncryptedData.
            let enc = unsafe { pp.d.encrypted };
            // SAFETY: its content, made with it, and its encrypted content.
            let Some(ec) = (unsafe { enc.as_ref() }).and_then(|e| unsafe { e.enc_data.as_mut() }) else {
                // SAFETY: the AlgorithmIdentifier made above.
                unsafe { X509_ALGOR_free(pbe) };
                break 'err false;
            };
            // SAFETY: the content's own algorithm.
            unsafe { X509_ALGOR_free(ec.algorithm) };
            ec.algorithm = pbe;
            // SAFETY: the content's own string, or NULL.
            unsafe { ASN1_OCTET_STRING_free(ec.enc_data) };
            // SAFETY: no preconditions.
            let it = unsafe { PKCS12_SAFEBAGS_it() };
            // SAFETY: the algorithm; the item; the password; the caller's bags.
            ec.enc_data = unsafe { PKCS12_item_i2d_encrypt_ex(pbe, it, pass, passlen, bags.cast(), 1, ctx, propq) };
            if ec.enc_data.is_null() {
                raise(PKCS12_R_ENCRYPT_ERROR, F);
                break 'err false;
            }
            true
        };
        // SAFETY: the fetched cipher, or NULL.
        unsafe { EVP_CIPHER_free(fetched) };
        if ok {
            return p7;
        }
        // SAFETY: the object made here.
        unsafe { PKCS7_free(p7) };
        ptr::null_mut()
    }
}

ffi_export! {
    /// The bags, encrypted with the password, as a new PKCS#7 EncryptedData. NULL on failure.
    ///
    /// # Safety
    /// As for `PKCS12_pack_p7encdata_ex`.
    pub unsafe extern "C" fn PKCS12_pack_p7encdata(pbe_nid: c_int, pass: *const c_char, passlen: c_int, salt: *mut c_uchar, saltlen: c_int, iter: c_int, bags: *mut stack_st_PKCS12_SAFEBAG) -> *mut PKCS7
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS12_pack_p7encdata_ex(pbe_nid, pass, passlen, salt, saltlen, iter, bags, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// The bags of a PKCS#7 EncryptedData, decrypted with the password, or NULL.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object; `pass` holds `passlen` octets (a C string if -1).
    pub unsafe extern "C" fn PKCS12_unpack_p7encdata(p7: *mut PKCS7, pass: *const c_char, passlen: c_int) -> *mut stack_st_PKCS12_SAFEBAG
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7.as_ref() }) else { return ptr::null_mut() };
        if type_nid(p) != NID_pkcs7_encrypted {
            return ptr::null_mut();
        }
        // SAFETY: the content of its type.
        let enc = unsafe { p.d.encrypted };
        // SAFETY: NULL or live, and its encrypted content.
        let Some(ec) = (unsafe { enc.as_ref() }).and_then(|e| unsafe { e.enc_data.as_ref() }) else {
            raise(PKCS12_R_DECODE_ERROR, "PKCS12_unpack_p7encdata");
            return ptr::null_mut();
        };
        // SAFETY: no preconditions.
        let it = unsafe { PKCS12_SAFEBAGS_it() };
        // SAFETY: the content's algorithm and string; the password; the object's context.
        unsafe { PKCS12_item_decrypt_d2i_ex(ec.algorithm, it, pass, passlen, ec.enc_data, 1, p.ctx.libctx, p.ctx.propq) }.cast()
    }
}

ffi_export! {
    /// A shrouded key bag's PKCS#8 key, decrypted with the password, in a library context, or
    /// NULL.
    ///
    /// # Safety
    /// `bag` is a live shrouded key bag; `pass` holds `passlen` octets (a C string if -1); `ctx`
    /// NULL or live; `propq` NULL or a C string.
    pub unsafe extern "C" fn PKCS12_decrypt_skey_ex(bag: *const PKCS12_SAFEBAG, pass: *const c_char, passlen: c_int, ctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut PKCS8_PRIV_KEY_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { bag_of(bag) }) else { return ptr::null_mut() };
        // SAFETY: as above; the bag's value, as OpenSSL takes it whatever the bag.
        unsafe { PKCS8_decrypt_ex(b.value.cast(), pass, passlen, ctx, propq) }
    }
}

ffi_export! {
    /// A shrouded key bag's PKCS#8 key, decrypted with the password, or NULL.
    ///
    /// # Safety
    /// As for `PKCS12_decrypt_skey_ex`.
    pub unsafe extern "C" fn PKCS12_decrypt_skey(bag: *const PKCS12_SAFEBAG, pass: *const c_char, passlen: c_int) -> *mut PKCS8_PRIV_KEY_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS12_decrypt_skey_ex(bag, pass, passlen, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// The contents as the PFX's authenticated safe's data: 1, or 0.
    ///
    /// # Safety
    /// `p12` is a live PFX whose authenticated safe is Data; `safes` a live list.
    pub unsafe extern "C" fn PKCS12_pack_authsafes(p12: *mut PKCS12, safes: *mut stack_st_PKCS7) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee; its authenticated safe.
        let Some(a) = (unsafe { pfx_of(p12) }).and_then(|p| unsafe { p.authsafes.as_mut() }) else { return 0 };
        // SAFETY: no preconditions.
        let it = unsafe { PKCS12_AUTHSAFES_it() };
        // SAFETY: the caller's contents; the data's slot.
        c_int::from(!unsafe { ASN1_item_pack(safes.cast(), it, (&raw mut a.d.data).cast()) }.is_null())
    }
}

/// `ossl_pkcs7_ctx_propagate`: the parent's library context and properties into `to`, and
/// through it.
///
/// # Safety
/// `from` and `to` are live objects.
unsafe fn ctx_propagate(from: &PKCS7, to: *mut PKCS7) -> bool {
    // SAFETY: the caller's guarantee.
    let t = unsafe { &mut *to };
    // SAFETY: its slots; the parent's properties.
    if !unsafe {
        set0_libctx(
            &mut t.ctx.libctx,
            &mut t.ctx.propq,
            from.ctx.libctx,
            from.ctx.propq,
        )
    } {
        return false;
    }
    // SAFETY: as above.
    unsafe { resolve_libctx(to) };
    true
}

ffi_export! {
    /// The contents of the PFX's authenticated safe, in its library context, or NULL.
    ///
    /// # Safety
    /// `p12` is NULL or a live PFX.
    pub unsafe extern "C" fn PKCS12_unpack_authsafes(p12: *const PKCS12) -> *mut stack_st_PKCS7
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        const F: &str = "PKCS12_unpack_authsafes";
        // SAFETY: the caller's guarantee; its authenticated safe.
        let Some(a) = (unsafe { pfx_of(p12) }).and_then(|p| unsafe { p.authsafes.as_ref() }) else { return ptr::null_mut() };
        if type_nid(a) != NID_pkcs7_data {
            raise(PKCS12_R_CONTENT_TYPE_NOT_DATA, F);
            return ptr::null_mut();
        }
        // SAFETY: the content of its type.
        let data = unsafe { a.d.data };
        if data.is_null() {
            raise(PKCS12_R_DECODE_ERROR, F);
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let it = unsafe { PKCS12_AUTHSAFES_it() };
        // SAFETY: the data; its context and properties.
        let p7s = unsafe { ASN1_item_unpack_ex(data, it, a.ctx.libctx, a.ctx.propq) };
        // SAFETY: the contents, or NULL.
        for i in 0..unsafe { OPENSSL_sk_num(p7s.cast()) } {
            // SAFETY: an index within them.
            let p7 = unsafe { OPENSSL_sk_value(p7s.cast(), i) }.cast::<PKCS7>();
            // SAFETY: the authenticated safe; one of its contents.
            if p7.is_null() || !unsafe { ctx_propagate(a, p7) } {
                // SAFETY: the contents decoded here.
                unsafe { OPENSSL_sk_pop_free(p7s.cast(), Some(p7_free)) };
                return ptr::null_mut();
            }
        }
        p7s.cast()
    }
}

/// `PKCS7_free` as a stack's free function.
pub(crate) unsafe extern "C" fn p7_free(p: *mut core::ffi::c_void) {
    // SAFETY: an element of a list of PKCS#7 objects.
    unsafe { PKCS7_free(p.cast()) };
}
