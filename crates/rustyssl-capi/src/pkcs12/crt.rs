//! Making a PFX (`p12_crt.c`, `p12_init.c`): bags of certificates, keys, and secrets, safe
//! contents, and `PKCS12_create`.

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PKCS12, ERR_R_ASN1_LIB, ERR_R_PKCS7_LIB, EVP_MAX_MD_SIZE, EVP_PKEY, NID_LocalKeySet,
    NID_aes_256_cbc, NID_ms_csp_name, NID_pbe_WithSHA1And40BitRC2_CBC, NID_pkcs7_data, NID_undef,
    OSSL_LIB_CTX, PKCS12, PKCS12_DEFAULT_ITER, PKCS12_R_CALLBACK_FAILED,
    PKCS12_R_INVALID_NULL_ARGUMENT, PKCS12_R_UNSUPPORTED_PKCS12_MODE, PKCS12_SAFEBAG,
    PKCS12_create_cb, X509, stack_st_PKCS7, stack_st_PKCS12_SAFEBAG, stack_st_X509,
};

use super::add::{PKCS12_pack_authsafes, PKCS12_pack_p7data, PKCS12_pack_p7encdata_ex, p7_free};
use super::asn::{PKCS12_SAFEBAG_free, PKCS12_free, PKCS12_new, bag_of, pfx_of};
use super::bags::{
    PKCS12_SAFEBAG_create_cert, PKCS12_SAFEBAG_create_pkcs8_encrypt_ex,
    PKCS12_SAFEBAG_create_secret, PKCS12_SAFEBAG_create0_p8inf, PKCS12_add_friendlyname_utf8,
    PKCS12_add_localkeyid,
};
use super::mutl::PKCS12_set_mac;
use crate::asn1::integer::ASN1_INTEGER_set;
use crate::asn1::string::ASN1_OCTET_STRING_new;
use crate::err;
use crate::evp::legacy_md::EVP_sha1;
use crate::evp::pkey::attrs::{EVP_PKEY_get_attr, EVP_PKEY_get_attr_by_NID};
use crate::evp::pkey::d2i::EVP_PKEY2PKCS8;
use crate::ffi::ffi_export;
use crate::objects::OBJ_nid2obj;
use crate::stack::{
    OPENSSL_sk_delete_ptr, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num,
    OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::x509::attrib::X509at_add1_attr;
use crate::x509::cert::{X509_check_private_key, X509_digest};
use crate::x509::p8::{PKCS8_PRIV_KEY_INFO_free, PKCS8_add_keyusage};
use crate::x509::trust::{X509_alias_get0, X509_keyid_get0};

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_PKCS12, reason, f);
}

/// `PKCS12_SAFEBAG_free` as a stack's free function.
unsafe extern "C" fn bag_free(p: *mut c_void) {
    // SAFETY: an element of a list of safe bags.
    unsafe { PKCS12_SAFEBAG_free(p.cast()) };
}

/// `copy_bag_attr`: the key's attribute `nid`, if it has one, onto the bag.
///
/// # Safety
/// `bag` and `pkey` are live.
unsafe fn copy_bag_attr(bag: *mut PKCS12_SAFEBAG, pkey: *const EVP_PKEY, nid: c_int) -> bool {
    // SAFETY: the caller's key.
    let idx = unsafe { EVP_PKEY_get_attr_by_NID(pkey, nid, -1) };
    if idx < 0 {
        return true;
    }
    // SAFETY: the caller's guarantee.
    let Some(b) = (unsafe { bag_of(bag) }) else {
        return false;
    };
    // SAFETY: the key; an index of its attributes.
    let a = unsafe { EVP_PKEY_get_attr(pkey, idx) };
    // SAFETY: the bag's attributes; the attribute, copied.
    !unsafe { X509at_add1_attr((&raw mut b.attrib).cast(), a) }.is_null()
}

/// `pkcs12_add_bag`: the bag onto the list (made if NULL), unless no list is given.
///
/// # Safety
/// `pbags` is NULL or holds NULL or a live list.
unsafe fn add_bag(pbags: *mut *mut stack_st_PKCS12_SAFEBAG, bag: *mut PKCS12_SAFEBAG) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(slot) = (unsafe { pbags.as_mut() }) else {
        return true;
    };
    let mut made = false;
    if slot.is_null() {
        // SAFETY: no preconditions.
        *slot = unsafe { OPENSSL_sk_new_null() }.cast();
        if slot.is_null() {
            return false;
        }
        made = true;
    }
    // SAFETY: the list; the bag.
    if unsafe { OPENSSL_sk_push((*slot).cast(), bag.cast()) } == 0 {
        if made {
            // SAFETY: the list made here.
            unsafe { OPENSSL_sk_free((*slot).cast()) };
            *slot = ptr::null_mut();
        }
        return false;
    }
    true
}

/// `pkcs12_remove_bag`: the bag out of the list, freed.
///
/// # Safety
/// `pbags` is NULL or holds a live list.
unsafe fn remove_bag(pbags: *mut *mut stack_st_PKCS12_SAFEBAG, bag: *mut PKCS12_SAFEBAG) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(&list) = (unsafe { pbags.as_ref() }) else {
        return true;
    };
    if bag.is_null() {
        return true;
    }
    // SAFETY: the list; the bag.
    let tmp = unsafe { OPENSSL_sk_delete_ptr(list.cast(), bag.cast()) };
    if tmp.is_null() {
        return false;
    }
    // SAFETY: the bag, out of the list.
    unsafe { PKCS12_SAFEBAG_free(tmp.cast()) };
    true
}

/// `pkcs12_add_cert_bag`: a certificate bag with the name and key identifier, onto the list.
///
/// # Safety
/// `cert` is live; `name` NULL or `namelen` octets (a C string if -1); `keyid` NULL or
/// `keyidlen` octets.
unsafe fn add_cert_bag(
    pbags: *mut *mut stack_st_PKCS12_SAFEBAG,
    cert: *mut X509,
    name: *const c_char,
    namelen: c_int,
    keyid: *mut c_uchar,
    keyidlen: c_int,
) -> *mut PKCS12_SAFEBAG {
    // SAFETY: the caller's guarantee.
    let bag = unsafe { PKCS12_SAFEBAG_create_cert(cert) };
    let ok = !bag.is_null()
        // SAFETY: the new bag; the name.
        && (name.is_null() || unsafe { PKCS12_add_friendlyname_utf8(bag, name, namelen) } != 0)
        // SAFETY: as above; the key identifier.
        && (keyid.is_null() || unsafe { PKCS12_add_localkeyid(bag, keyid, keyidlen) } != 0)
        // SAFETY: the caller's list; the bag.
        && unsafe { add_bag(pbags, bag) };
    if !ok {
        // SAFETY: the bag made here, or NULL.
        unsafe { PKCS12_SAFEBAG_free(bag) };
        return ptr::null_mut();
    }
    bag
}

ffi_export! {
    /// Adds a certificate bag (with the certificate's alias and key identifier) to the list.
    /// The bag, or NULL.
    ///
    /// # Safety
    /// `pbags` is NULL or holds NULL or a live list; `cert` a live certificate.
    pub unsafe extern "C" fn PKCS12_add_cert(pbags: *mut *mut stack_st_PKCS12_SAFEBAG, cert: *mut X509) -> *mut PKCS12_SAFEBAG
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        let mut namelen: c_int = -1;
        let mut keyidlen: c_int = -1;
        // SAFETY: the caller's certificate; room for the length.
        let name = unsafe { X509_alias_get0(cert, &mut namelen) };
        // SAFETY: as above.
        let keyid = unsafe { X509_keyid_get0(cert, &mut keyidlen) };
        // SAFETY: as above; the certificate's own alias and identifier.
        unsafe { add_cert_bag(pbags, cert, name.cast(), namelen, keyid, keyidlen) }
    }
}

ffi_export! {
    /// Adds a key bag (shrouded with the password by `nid_key`, or plain for -1), with the key
    /// usage if nonzero, to the list, in a library context. The bag, or NULL.
    ///
    /// # Safety
    /// `pbags` is NULL or holds NULL or a live list; `key` a live key; `pass` NULL or a C
    /// string; `ctx` NULL or live; `propq` NULL or a C string.
    pub unsafe extern "C" fn PKCS12_add_key_ex(pbags: *mut *mut stack_st_PKCS12_SAFEBAG, key: *mut EVP_PKEY, key_usage: c_int, iter: c_int, nid_key: c_int, pass: *const c_char, ctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut PKCS12_SAFEBAG
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // A PKCS#8 structure.
        // SAFETY: the caller's guarantee.
        let mut p8 = unsafe { EVP_PKEY2PKCS8(key) };
        if p8.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the new key.
        if key_usage != 0 && unsafe { PKCS8_add_keyusage(p8, key_usage) } == 0 {
            // SAFETY: as above.
            unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
            return ptr::null_mut();
        }
        let bag = if nid_key == -1 {
            // SAFETY: the key, which the bag takes.
            let b = unsafe { PKCS12_SAFEBAG_create0_p8inf(p8) };
            if !b.is_null() {
                p8 = ptr::null_mut();
            }
            b
        } else {
            // SAFETY: as above; this doesn't take the key.
            unsafe { PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(nid_key, pass, -1, ptr::null_mut(), 0, iter, p8, ctx, propq) }
        };
        // SAFETY: the key, if not taken, or NULL.
        unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
        // SAFETY: the caller's list; the bag.
        if bag.is_null() || !unsafe { add_bag(pbags, bag) } {
            // SAFETY: the bag made here, or NULL.
            unsafe { PKCS12_SAFEBAG_free(bag) };
            return ptr::null_mut();
        }
        bag
    }
}

ffi_export! {
    /// Adds a key bag to the list. The bag, or NULL.
    ///
    /// # Safety
    /// As for `PKCS12_add_key_ex`.
    pub unsafe extern "C" fn PKCS12_add_key(pbags: *mut *mut stack_st_PKCS12_SAFEBAG, key: *mut EVP_PKEY, key_usage: c_int, iter: c_int, nid_key: c_int, pass: *const c_char) -> *mut PKCS12_SAFEBAG
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS12_add_key_ex(pbags, key, key_usage, iter, nid_key, pass, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Adds a secret bag of type `nid_type` holding `value` (as an OCTET STRING) to the list.
    /// The bag, or NULL.
    ///
    /// # Safety
    /// `pbags` is NULL or holds NULL or a live list; `value` holds `len` octets.
    pub unsafe extern "C" fn PKCS12_add_secret(pbags: *mut *mut stack_st_PKCS12_SAFEBAG, nid_type: c_int, value: *const c_uchar, len: c_int) -> *mut PKCS12_SAFEBAG
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let bag = unsafe { PKCS12_SAFEBAG_create_secret(nid_type, rustyssl_abi::V_ASN1_OCTET_STRING, value, len) };
        // SAFETY: as above; the bag.
        if bag.is_null() || !unsafe { add_bag(pbags, bag) } {
            // SAFETY: the bag made here, or NULL.
            unsafe { PKCS12_SAFEBAG_free(bag) };
            return ptr::null_mut();
        }
        bag
    }
}

ffi_export! {
    /// Adds the bags to the list of contents (made if NULL): as Data for -1, else encrypted
    /// with the password by `nid_safe` (40-bit RC2 for 0). 1, or 0.
    ///
    /// # Safety
    /// `psafes` holds NULL or a live list; `bags` a live list; `pass` NULL or a C string;
    /// `ctx` NULL or live; `propq` NULL or a C string.
    pub unsafe extern "C" fn PKCS12_add_safe_ex(psafes: *mut *mut stack_st_PKCS7, bags: *mut stack_st_PKCS12_SAFEBAG, nid_safe: c_int, iter: c_int, pass: *const c_char, ctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let Some(slot) = (unsafe { psafes.as_mut() }) else { return 0 };
        let mut made = false;
        if slot.is_null() {
            // SAFETY: no preconditions.
            *slot = unsafe { OPENSSL_sk_new_null() }.cast();
            if slot.is_null() {
                return 0;
            }
            made = true;
        }
        let nid_safe = if nid_safe == 0 { NID_pbe_WithSHA1And40BitRC2_CBC } else { nid_safe };
        let p7 = if nid_safe == -1 {
            // SAFETY: the caller's bags.
            unsafe { PKCS12_pack_p7data(bags) }
        } else {
            // SAFETY: as above; the password.
            unsafe { PKCS12_pack_p7encdata_ex(nid_safe, pass, -1, ptr::null_mut(), 0, iter, bags, ctx, propq) }
        };
        // SAFETY: the list; the new content.
        if !p7.is_null() && unsafe { OPENSSL_sk_push((*slot).cast(), p7.cast()) } != 0 {
            return 1;
        }
        if made {
            // SAFETY: the list made here.
            unsafe { OPENSSL_sk_free((*slot).cast()) };
            *slot = ptr::null_mut();
        }
        // SAFETY: the content made here, or NULL.
        unsafe { crate::pkcs7::PKCS7_free(p7) };
        0
    }
}

ffi_export! {
    /// Adds the bags to the list of contents. 1, or 0.
    ///
    /// # Safety
    /// As for `PKCS12_add_safe_ex`.
    pub unsafe extern "C" fn PKCS12_add_safe(psafes: *mut *mut stack_st_PKCS7, bags: *mut stack_st_PKCS12_SAFEBAG, nid_safe: c_int, iter: c_int, pass: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS12_add_safe_ex(psafes, bags, nid_safe, iter, pass, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// A new PFX whose authenticated safe (of type `mode`, only Data) is empty, in a library
    /// context, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or live; `propq` NULL or a C string.
    pub unsafe extern "C" fn PKCS12_init_ex(mode: c_int, ctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut PKCS12
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        const F: &str = "PKCS12_init_ex";
        // SAFETY: no preconditions.
        let p12 = unsafe { PKCS12_new() };
        // SAFETY: the new PFX, or NULL; its authenticated safe, made with it.
        let Some((p, a)) = (unsafe { pfx_of(p12) }).and_then(|p| unsafe { p.authsafes.as_mut() }.map(|a| (p.version, a))) else {
            raise(ERR_R_ASN1_LIB, F);
            // SAFETY: the PFX made here, or NULL.
            unsafe { PKCS12_free(p12) };
            return ptr::null_mut();
        };
        let ok = 'err: {
            // SAFETY: its version, made with it.
            if unsafe { ASN1_INTEGER_set(p, 3) } == 0 {
                break 'err false;
            }
            // SAFETY: any NID.
            a.type_ = unsafe { OBJ_nid2obj(mode) };
            // SAFETY: its slots; the caller's properties.
            if !unsafe { crate::x509::cert::set0_libctx(&mut a.ctx.libctx, &mut a.ctx.propq, ctx, propq) } {
                raise(ERR_R_PKCS7_LIB, F);
                break 'err false;
            }
            if mode != NID_pkcs7_data {
                raise(PKCS12_R_UNSUPPORTED_PKCS12_MODE, F);
                break 'err false;
            }
            // SAFETY: no preconditions.
            a.d.data = unsafe { ASN1_OCTET_STRING_new() };
            // SAFETY: the content of its type.
            if unsafe { a.d.data }.is_null() {
                raise(ERR_R_ASN1_LIB, F);
                break 'err false;
            }
            true
        };
        if ok {
            return p12;
        }
        // SAFETY: the PFX made here.
        unsafe { PKCS12_free(p12) };
        ptr::null_mut()
    }
}

ffi_export! {
    /// A new PFX whose authenticated safe (of type `mode`, only Data) is empty, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn PKCS12_init(mode: c_int) -> *mut PKCS12
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: no context or properties.
        unsafe { PKCS12_init_ex(mode, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// A new PFX of the contents (as Data for `nid_p7` 0), in a library context, or NULL.
    ///
    /// # Safety
    /// `safes` is a live list; `ctx` NULL or live; `propq` NULL or a C string.
    pub unsafe extern "C" fn PKCS12_add_safes_ex(safes: *mut stack_st_PKCS7, nid_p7: c_int, ctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut PKCS12
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        let nid_p7 = if nid_p7 <= 0 { NID_pkcs7_data } else { nid_p7 };
        // SAFETY: the caller's guarantee.
        let p12 = unsafe { PKCS12_init_ex(nid_p7, ctx, propq) };
        // SAFETY: the new PFX; the caller's contents.
        if !p12.is_null() && unsafe { PKCS12_pack_authsafes(p12, safes) } == 0 {
            // SAFETY: the PFX made here.
            unsafe { PKCS12_free(p12) };
            return ptr::null_mut();
        }
        p12
    }
}

ffi_export! {
    /// A new PFX of the contents, or NULL.
    ///
    /// # Safety
    /// `safes` is a live list.
    pub unsafe extern "C" fn PKCS12_add_safes(safes: *mut stack_st_PKCS7, nid_p7: c_int) -> *mut PKCS12
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS12_add_safes_ex(safes, nid_p7, ptr::null_mut(), ptr::null()) }
    }
}

/// The callback's verdict on a bag: `false` to fail, else the bag kept or (0) removed.
///
/// # Safety
/// `cb` is NULL or the caller's callback; `bags` holds the bag's list.
unsafe fn ask(
    cb: PKCS12_create_cb,
    cbarg: *mut c_void,
    bags: *mut *mut stack_st_PKCS12_SAFEBAG,
    bag: *mut PKCS12_SAFEBAG,
) -> bool {
    let Some(f) = cb else { return true };
    // SAFETY: the caller's callback, with no lock held; the bag and its argument.
    match unsafe { f(bag, cbarg) } {
        -1 => {
            raise(PKCS12_R_CALLBACK_FAILED, "PKCS12_create_ex2");
            false
        }
        0 => {
            // SAFETY: the bag's list.
            unsafe { remove_bag(bags, bag) };
            true
        }
        _ => true,
    }
}

ffi_export! {
    /// A new PFX of the key (shrouded by `nid_key`, AES-256-CBC for 0), its certificate, and
    /// the others (encrypted by `nid_cert`, AES-256-CBC for 0; -1 for neither), with the
    /// friendly name, the key's local identifier, and a SHA-256 MAC (none for `mac_iter` -1);
    /// each bag shown to the callback, which keeps (1), drops (0), or fails (-1) it. NULL on
    /// failure.
    ///
    /// # Safety
    /// `pass` and `name` are NULL or C strings; the others NULL or live.
    pub unsafe extern "C" fn PKCS12_create_ex2(pass: *const c_char, name: *const c_char, pkey: *mut EVP_PKEY, cert: *mut X509, ca: *mut stack_st_X509, nid_key: c_int, nid_cert: c_int, iter: c_int, mac_iter: c_int, keytype: c_int, ctx: *mut OSSL_LIB_CTX, propq: *const c_char, cb: PKCS12_create_cb, cbarg: *mut c_void) -> *mut PKCS12
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        let nid_cert = if nid_cert == NID_undef { NID_aes_256_cbc } else { nid_cert };
        let nid_key = if nid_key == NID_undef { NID_aes_256_cbc } else { nid_key };
        let iter = if iter == 0 { PKCS12_DEFAULT_ITER } else { iter };
        let mac_iter = if mac_iter == 0 { PKCS12_DEFAULT_ITER } else { mac_iter };
        if pkey.is_null() && cert.is_null() && ca.is_null() {
            raise(PKCS12_R_INVALID_NULL_ARGUMENT, "PKCS12_create_ex2");
            return ptr::null_mut();
        }
        let mut keyid = [0u8; EVP_MAX_MD_SIZE as usize];
        let mut keyidlen: c_uint = 0;
        if !pkey.is_null() && !cert.is_null() {
            // SAFETY: the caller's certificate and key.
            if unsafe { X509_check_private_key(cert, pkey) } == 0 {
                return ptr::null_mut();
            }
            // SAFETY: no preconditions.
            let sha1 = unsafe { EVP_sha1() };
            // SAFETY: as above; a built-in digest; room for it.
            if unsafe { X509_digest(cert, sha1, keyid.as_mut_ptr(), &mut keyidlen) } == 0 {
                return ptr::null_mut();
            }
        }
        let keyidlen_i = c_int::try_from(keyidlen).unwrap_or(0);
        let mut name = name;
        let mut namelen: c_int = -1;
        let mut safes: *mut stack_st_PKCS7 = ptr::null_mut();
        let mut bags: *mut stack_st_PKCS12_SAFEBAG = ptr::null_mut();
        let mut p12: *mut PKCS12 = ptr::null_mut();
        let ok = 'err: {
            if !cert.is_null() {
                if name.is_null() {
                    // SAFETY: the caller's certificate; room for the length.
                    name = unsafe { X509_alias_get0(cert, &mut namelen) }.cast();
                }
                let (pkeyid, pkeyidlen) = if keyidlen > 0 {
                    (keyid.as_mut_ptr(), keyidlen_i)
                } else {
                    let mut n: c_int = -1;
                    // SAFETY: as above.
                    (unsafe { X509_keyid_get0(cert, &mut n) }, n)
                };
                // SAFETY: the list; the certificate, its name and identifier.
                let bag = unsafe { add_cert_bag(&mut bags, cert, name, namelen, pkeyid, pkeyidlen) };
                // SAFETY: the caller's callback; the list.
                if !unsafe { ask(cb, cbarg, &mut bags, bag) } {
                    break 'err false;
                }
            }
            // All the other certificates.
            // SAFETY: the caller's list, or NULL.
            for i in 0..unsafe { OPENSSL_sk_num(ca.cast()) } {
                // SAFETY: an index within it.
                let x = unsafe { OPENSSL_sk_value(ca.cast(), i) }.cast::<X509>();
                // SAFETY: the list; a certificate.
                let bag = unsafe { PKCS12_add_cert(&mut bags, x) };
                if bag.is_null() {
                    break 'err false;
                }
                // SAFETY: as above.
                if !unsafe { ask(cb, cbarg, &mut bags, bag) } {
                    break 'err false;
                }
            }
            // SAFETY: the contents' slot; the bags; the password.
            if !bags.is_null() && unsafe { PKCS12_add_safe_ex(&mut safes, bags, nid_cert, iter, pass, ctx, propq) } == 0 {
                break 'err false;
            }
            // SAFETY: the bags, packed.
            unsafe { OPENSSL_sk_pop_free(bags.cast(), Some(bag_free)) };
            bags = ptr::null_mut();
            if !pkey.is_null() {
                // SAFETY: the list; the caller's key and password.
                let bag = unsafe { PKCS12_add_key_ex(&mut bags, pkey, keytype, iter, nid_key, pass, ctx, propq) };
                if bag.is_null() {
                    break 'err false;
                }
                // SAFETY: the new bag; the caller's key.
                if !unsafe { copy_bag_attr(bag, pkey, NID_ms_csp_name) } || !unsafe { copy_bag_attr(bag, pkey, NID_LocalKeySet) } {
                    break 'err false;
                }
                // SAFETY: as above; the name, a C string.
                if !name.is_null() && unsafe { PKCS12_add_friendlyname_utf8(bag, name, -1) } == 0 {
                    break 'err false;
                }
                // SAFETY: as above; the key identifier.
                if keyidlen > 0 && unsafe { PKCS12_add_localkeyid(bag, keyid.as_mut_ptr(), keyidlen_i) } == 0 {
                    break 'err false;
                }
                // SAFETY: as above.
                if !unsafe { ask(cb, cbarg, &mut bags, bag) } {
                    break 'err false;
                }
            }
            // SAFETY: as above, as Data.
            if !bags.is_null() && unsafe { PKCS12_add_safe_ex(&mut safes, bags, -1, 0, ptr::null(), ptr::null_mut(), ptr::null()) } == 0 {
                break 'err false;
            }
            // SAFETY: as above.
            unsafe { OPENSSL_sk_pop_free(bags.cast(), Some(bag_free)) };
            bags = ptr::null_mut();
            // SAFETY: the contents.
            p12 = unsafe { PKCS12_add_safes_ex(safes, 0, ctx, propq) };
            if p12.is_null() {
                break 'err false;
            }
            // SAFETY: the contents, packed.
            unsafe { OPENSSL_sk_pop_free(safes.cast(), Some(p7_free)) };
            safes = ptr::null_mut();
            // SAFETY: the new PFX; the password.
            if mac_iter != -1 && unsafe { PKCS12_set_mac(p12, pass, -1, ptr::null_mut(), 0, mac_iter, ptr::null()) } == 0 {
                break 'err false;
            }
            true
        };
        if ok {
            return p12;
        }
        // SAFETY: made here, or NULL.
        unsafe { PKCS12_free(p12) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_pop_free(safes.cast(), Some(p7_free)) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_pop_free(bags.cast(), Some(bag_free)) };
        ptr::null_mut()
    }
}

ffi_export! {
    /// A new PFX of the key, certificate, and others, in a library context, or NULL.
    ///
    /// # Safety
    /// As for `PKCS12_create_ex2`.
    pub unsafe extern "C" fn PKCS12_create_ex(pass: *const c_char, name: *const c_char, pkey: *mut EVP_PKEY, cert: *mut X509, ca: *mut stack_st_X509, nid_key: c_int, nid_cert: c_int, iter: c_int, mac_iter: c_int, keytype: c_int, ctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut PKCS12
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS12_create_ex2(pass, name, pkey, cert, ca, nid_key, nid_cert, iter, mac_iter, keytype, ctx, propq, None, ptr::null_mut()) }
    }
}

ffi_export! {
    /// A new PFX of the key, certificate, and others, or NULL.
    ///
    /// # Safety
    /// As for `PKCS12_create_ex2`.
    pub unsafe extern "C" fn PKCS12_create(pass: *const c_char, name: *const c_char, pkey: *mut EVP_PKEY, cert: *mut X509, ca: *mut stack_st_X509, nid_key: c_int, nid_cert: c_int, iter: c_int, mac_iter: c_int, keytype: c_int) -> *mut PKCS12
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS12_create_ex(pass, name, pkey, cert, ca, nid_key, nid_cert, iter, mac_iter, keytype, ptr::null_mut(), ptr::null()) }
    }
}
