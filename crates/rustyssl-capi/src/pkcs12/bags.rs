//! Safe bags (`p12_sbag.c`, `p12_attr.c`, and `p12_add.c`'s packing of one): their types and
//! values, certificate, CRL, secret, and key bags, and their attributes (friendly name, local
//! key identifier, and others).

use core::ffi::{c_char, c_int, c_uchar};
use core::ptr;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_OBJECT, ASN1_STRING, ASN1_TYPE, ERR_LIB_PKCS12, ERR_R_ASN1_LIB, EVP_CIPHER,
    MBSTRING_ASC, MBSTRING_BMP, MBSTRING_UTF8, NID_certBag, NID_crlBag, NID_friendlyName,
    NID_keyBag, NID_localKeyID, NID_ms_csp_name, NID_pkcs8ShroudedKeyBag, NID_safeContentsBag,
    NID_sdsiCertificate, NID_secretBag, NID_undef, NID_x509Certificate, NID_x509Crl, OSSL_LIB_CTX,
    PKCS8_PRIV_KEY_INFO, PKCS12_R_ENCODE_ERROR, PKCS12_R_INVALID_TYPE, PKCS12_SAFEBAG,
    V_ASN1_BMPSTRING, V_ASN1_OCTET_STRING, X509, X509_CRL, X509_SIG, stack_st_PKCS12_SAFEBAG,
    stack_st_X509_ATTRIBUTE,
};

use super::asn::{Bags, PKCS12_BAGS_free, PKCS12_BAGS_new, PKCS12_SAFEBAG_new, SafeBag, bag_of};
use crate::asn1::any::ASN1_TYPE_set;
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set};
use crate::asn1::tpl::items::ASN1_TYPE_new;
use crate::asn1::tpl::util::{ASN1_item_pack, ASN1_item_unpack, ASN1_item_unpack_ex};
use crate::err::{self, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free};
use crate::evp::legacy_cipher::EVP_get_cipherbyname;
use crate::ffi::ffi_export;
use crate::objects::{OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid};
use crate::pkcs8_crypt::PKCS8_encrypt_ex;
use crate::stack::OPENSSL_sk_free;
use crate::x509::attrib::{
    X509_ATTRIBUTE_get0_type, X509at_add1_attr_by_NID, X509at_add1_attr_by_txt, X509at_get_attr,
    X509at_get_attr_by_NID,
};
use crate::x509::cert::{X509_free, X509_it, cert_of, set0_libctx};
use crate::x509::crl::{X509_CRL_free, X509_CRL_it, crl_of};
use crate::x509::sig::X509_SIG_free;

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_PKCS12, reason, f);
}

/// The bag's type's NID (`NID_undef` for NULL).
fn nid(bag: &SafeBag) -> c_int {
    // SAFETY: its object, or NULL.
    unsafe { OBJ_obj2nid(bag.type_) }
}

/// A certificate, CRL, or secret bag's inner bag.
fn inner<'a>(bag: &SafeBag) -> Option<&'a mut Bags> {
    if ![NID_certBag, NID_crlBag, NID_secretBag].contains(&nid(bag)) {
        return None;
    }
    // SAFETY: the value of its type, NULL or live.
    unsafe { bag.value.cast::<Bags>().as_mut() }
}

/// The inner bag's type's NID.
fn inner_nid(b: &Bags) -> c_int {
    // SAFETY: its object, or NULL.
    unsafe { OBJ_obj2nid(b.type_) }
}

ffi_export! {
    /// Packs `obj` (of `it`) into the OCTET STRING of a new bag of type `nid1`, in a new safe
    /// bag of type `nid2`. NULL on failure.
    ///
    /// # Safety
    /// `obj` is a live value of `it`.
    pub unsafe extern "C" fn PKCS12_item_pack_safebag(obj: *mut core::ffi::c_void, it: *const ASN1_ITEM, nid1: c_int, nid2: c_int) -> *mut PKCS12_SAFEBAG
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        const F: &str = "PKCS12_item_pack_safebag";
        // SAFETY: no preconditions.
        let bag = unsafe { PKCS12_BAGS_new() };
        // SAFETY: the new bag, or NULL.
        let Some(b) = (unsafe { bag.cast::<Bags>().as_mut() }) else {
            raise(ERR_R_ASN1_LIB, F);
            return ptr::null_mut();
        };
        // SAFETY: any NID.
        b.type_ = unsafe { OBJ_nid2obj(nid1) };
        // SAFETY: the caller's guarantee; the bag's value slot.
        if unsafe { ASN1_item_pack(obj, it, (&raw mut b.value).cast()) }.is_null() {
            raise(ERR_R_ASN1_LIB, F);
            // SAFETY: the bag made here.
            unsafe { PKCS12_BAGS_free(bag) };
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let safebag = unsafe { PKCS12_SAFEBAG_new() };
        // SAFETY: the new safe bag, or NULL.
        let Some(s) = (unsafe { bag_of(safebag) }) else {
            raise(ERR_R_ASN1_LIB, F);
            // SAFETY: as above.
            unsafe { PKCS12_BAGS_free(bag) };
            return ptr::null_mut();
        };
        s.value = bag.cast();
        // SAFETY: any NID.
        s.type_ = unsafe { OBJ_nid2obj(nid2) };
        safebag
    }
}

ffi_export! {
    /// A safe bag of the certificate. NULL on failure.
    ///
    /// # Safety
    /// `x509` is a live certificate.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_create_cert(x509: *mut X509) -> *mut PKCS12_SAFEBAG
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_it() };
        // SAFETY: the caller's certificate, of its item.
        unsafe { PKCS12_item_pack_safebag(x509.cast(), it, NID_x509Certificate, NID_certBag) }
    }
}

ffi_export! {
    /// A safe bag of the CRL. NULL on failure.
    ///
    /// # Safety
    /// `crl` is a live CRL.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_create_crl(crl: *mut X509_CRL) -> *mut PKCS12_SAFEBAG
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_CRL_it() };
        // SAFETY: the caller's CRL, of its item.
        unsafe { PKCS12_item_pack_safebag(crl.cast(), it, NID_x509Crl, NID_crlBag) }
    }
}

ffi_export! {
    /// A secret bag of type `type_` with `value` (only as an OCTET STRING, `vtype`). NULL on
    /// failure.
    ///
    /// # Safety
    /// `value` holds `len` octets.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_create_secret(type_: c_int, vtype: c_int, value: *const c_uchar, len: c_int) -> *mut PKCS12_SAFEBAG
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        const F: &str = "PKCS12_SAFEBAG_create_secret";
        // SAFETY: no preconditions.
        let bag = unsafe { PKCS12_BAGS_new() };
        // SAFETY: the new bag, or NULL.
        let Some(b) = (unsafe { bag.cast::<Bags>().as_mut() }) else {
            raise(ERR_R_ASN1_LIB, F);
            return ptr::null_mut();
        };
        // SAFETY: any NID.
        b.type_ = unsafe { OBJ_nid2obj(type_) };
        let ok = 'err: {
            if vtype != V_ASN1_OCTET_STRING {
                raise(PKCS12_R_INVALID_TYPE, F);
                break 'err false;
            }
            // SAFETY: no preconditions.
            let s = unsafe { ASN1_OCTET_STRING_new() };
            if s.is_null() {
                raise(ERR_R_ASN1_LIB, F);
                break 'err false;
            }
            // Pack the data into an OCTET STRING.
            // SAFETY: the new string; the caller's octets.
            if unsafe { ASN1_OCTET_STRING_set(s, value, len) } == 0 {
                // SAFETY: the string made here.
                unsafe { ASN1_OCTET_STRING_free(s) };
                raise(PKCS12_R_ENCODE_ERROR, F);
                break 'err false;
            }
            // SAFETY: no preconditions.
            let t = unsafe { ASN1_TYPE_new() };
            if t.is_null() {
                // SAFETY: as above.
                unsafe { ASN1_OCTET_STRING_free(s) };
                raise(ERR_R_ASN1_LIB, F);
                break 'err false;
            }
            // SAFETY: the new type, taking the string.
            unsafe { ASN1_TYPE_set(t, vtype, s.cast()) };
            b.value = t.cast();
            true
        };
        // SAFETY: no preconditions.
        let safebag = if ok { unsafe { PKCS12_SAFEBAG_new() } } else { ptr::null_mut() };
        // SAFETY: the new safe bag, or NULL.
        let Some(s) = (unsafe { bag_of(safebag) }) else {
            if ok {
                raise(ERR_R_ASN1_LIB, F);
            }
            // SAFETY: the bag made here.
            unsafe { PKCS12_BAGS_free(bag) };
            return ptr::null_mut();
        };
        s.value = bag.cast();
        // SAFETY: a built-in NID.
        s.type_ = unsafe { OBJ_nid2obj(NID_secretBag) };
        safebag
    }
}

/// A new safe bag of type `nid` holding `value`, or NULL.
fn create0(nid: c_int, value: *mut core::ffi::c_void, f: &str) -> *mut PKCS12_SAFEBAG {
    // SAFETY: no preconditions.
    let bag = unsafe { PKCS12_SAFEBAG_new() };
    // SAFETY: the new safe bag, or NULL.
    let Some(b) = (unsafe { bag_of(bag) }) else {
        raise(ERR_R_ASN1_LIB, f);
        return ptr::null_mut();
    };
    // SAFETY: a built-in NID.
    b.type_ = unsafe { OBJ_nid2obj(nid) };
    b.value = value;
    bag
}

ffi_export! {
    /// A key bag taking the PKCS#8 key. NULL on failure.
    ///
    /// # Safety
    /// `p8` is a live key, taken on success.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_create0_p8inf(p8: *mut PKCS8_PRIV_KEY_INFO) -> *mut PKCS12_SAFEBAG
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        create0(NID_keyBag, p8.cast(), "PKCS12_SAFEBAG_create0_p8inf")
    }
}

ffi_export! {
    /// A shrouded key bag taking the encrypted PKCS#8 key. NULL on failure.
    ///
    /// # Safety
    /// `p8` is a live encrypted key, taken on success.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_create0_pkcs8(p8: *mut X509_SIG) -> *mut PKCS12_SAFEBAG
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        create0(NID_pkcs8ShroudedKeyBag, p8.cast(), "PKCS12_SAFEBAG_create0_pkcs8")
    }
}

ffi_export! {
    /// A shrouded key bag of the PKCS#8 key, encrypted with the password by `pbe_nid` (a
    /// cipher's NID for PBES2, else a PKCS#12 PBE). NULL on failure.
    ///
    /// # Safety
    /// `pass` holds `passlen` octets (a C string if -1); `salt` NULL or `saltlen` octets;
    /// `p8inf` a live key; `ctx` NULL or live; `propq` NULL or a C string.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(pbe_nid: c_int, pass: *const c_char, passlen: c_int, salt: *mut c_uchar, saltlen: c_int, iter: c_int, p8inf: *mut PKCS8_PRIV_KEY_INFO, ctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut PKCS12_SAFEBAG
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let (cipher, fetched) = unsafe { pbe_cipher(pbe_nid, ctx, propq) };
        let pbe_nid = if cipher.is_null() { pbe_nid } else { -1 };
        // SAFETY: as above.
        let p8 = unsafe { PKCS8_encrypt_ex(pbe_nid, cipher, pass, passlen, salt, saltlen, iter, p8inf, ctx, propq) };
        let bag = if p8.is_null() {
            ptr::null_mut()
        } else {
            create0(NID_pkcs8ShroudedKeyBag, p8.cast(), "PKCS12_SAFEBAG_create0_pkcs8")
        };
        if bag.is_null() {
            // SAFETY: the encrypted key, or NULL.
            unsafe { X509_SIG_free(p8) };
        }
        // SAFETY: the cipher fetched, or NULL.
        unsafe { EVP_CIPHER_free(fetched) };
        bag
    }
}

ffi_export! {
    /// A shrouded key bag of the PKCS#8 key, encrypted with the password. NULL on failure.
    ///
    /// # Safety
    /// As for `PKCS12_SAFEBAG_create_pkcs8_encrypt_ex`.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_create_pkcs8_encrypt(pbe_nid: c_int, pass: *const c_char, passlen: c_int, salt: *mut c_uchar, saltlen: c_int, iter: c_int, p8inf: *mut PKCS8_PRIV_KEY_INFO) -> *mut PKCS12_SAFEBAG
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(pbe_nid, pass, passlen, salt, saltlen, iter, p8inf, ptr::null_mut(), ptr::null()) }
    }
}

/// The cipher `pbe_nid` names (fetched, or else built in), if it is one, and the fetched one
/// to free.
///
/// # Safety
/// `ctx` is NULL or live; `propq` NULL or a C string.
pub(crate) unsafe fn pbe_cipher(
    pbe_nid: c_int,
    ctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> (*const EVP_CIPHER, *mut EVP_CIPHER) {
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: any NID.
    let sn = unsafe { OBJ_nid2sn(pbe_nid) };
    // SAFETY: NULL or a static name; the caller's context and properties.
    let fetched = unsafe { EVP_CIPHER_fetch(ctx, sn, propq) };
    let cipher = if fetched.is_null() {
        // SAFETY: as above.
        unsafe { EVP_get_cipherbyname(sn) }
    } else {
        fetched.cast_const()
    };
    // SAFETY: no preconditions.
    unsafe { ERR_pop_to_mark() };
    (cipher, fetched)
}

ffi_export! {
    /// A key bag's PKCS#8 key, or NULL.
    ///
    /// # Safety
    /// `bag` is NULL or a live safe bag.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_get0_p8inf(bag: *const PKCS12_SAFEBAG) -> *const PKCS8_PRIV_KEY_INFO
    where failure = ptr::null(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { bag_of(bag) }) else { return ptr::null() };
        if nid(b) != NID_keyBag {
            return ptr::null();
        }
        b.value.cast()
    }
}

ffi_export! {
    /// A shrouded key bag's encrypted key, or NULL.
    ///
    /// # Safety
    /// `bag` is NULL or a live safe bag.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_get0_pkcs8(bag: *const PKCS12_SAFEBAG) -> *const X509_SIG
    where failure = ptr::null(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { bag_of(bag) }) else { return ptr::null() };
        if nid(b) != NID_pkcs8ShroudedKeyBag {
            return ptr::null();
        }
        b.value.cast()
    }
}

ffi_export! {
    /// A SafeContents bag's bags, or NULL.
    ///
    /// # Safety
    /// `bag` is NULL or a live safe bag.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_get0_safes(bag: *const PKCS12_SAFEBAG) -> *const stack_st_PKCS12_SAFEBAG
    where failure = ptr::null(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { bag_of(bag) }) else { return ptr::null() };
        if nid(b) != NID_safeContentsBag {
            return ptr::null();
        }
        b.value.cast()
    }
}

ffi_export! {
    /// The bag's type.
    ///
    /// # Safety
    /// `bag` is NULL or a live safe bag.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_get0_type(bag: *const PKCS12_SAFEBAG) -> *const ASN1_OBJECT
    where failure = ptr::null(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { bag_of(bag) }.map_or(ptr::null(), |b| b.type_.cast_const())
    }
}

ffi_export! {
    /// The bag's type's NID.
    ///
    /// # Safety
    /// `bag` is NULL or a live safe bag.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_get_nid(bag: *const PKCS12_SAFEBAG) -> c_int
    where failure = NID_undef, library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { bag_of(bag) }.map_or(NID_undef, |b| nid(b))
    }
}

ffi_export! {
    /// A certificate, CRL, or secret bag's inner type's NID; -1 for other bags.
    ///
    /// # Safety
    /// `bag` is NULL or a live safe bag.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_get_bag_nid(bag: *const PKCS12_SAFEBAG) -> c_int
    where failure = -1, library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { bag_of(bag) }) else { return -1 };
        inner(b).map_or(-1, |i| inner_nid(i))
    }
}

ffi_export! {
    /// A certificate, CRL, or secret bag's inner type, or NULL.
    ///
    /// # Safety
    /// `bag` is NULL or a live safe bag.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_get0_bag_type(bag: *const PKCS12_SAFEBAG) -> *const ASN1_OBJECT
    where failure = ptr::null(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { bag_of(bag) }) else { return ptr::null() };
        inner(b).map_or(ptr::null(), |i| i.type_.cast_const())
    }
}

ffi_export! {
    /// A secret (or other) bag's value, or NULL for certificate and CRL bags and others.
    ///
    /// # Safety
    /// `bag` is NULL or a live safe bag.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_get0_bag_obj(bag: *const PKCS12_SAFEBAG) -> *const ASN1_TYPE
    where failure = ptr::null(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { bag_of(bag) }) else { return ptr::null() };
        let Some(i) = inner(b) else { return ptr::null() };
        if [NID_x509Certificate, NID_x509Crl, NID_sdsiCertificate].contains(&inner_nid(i)) {
            return ptr::null();
        }
        i.value.cast()
    }
}

/// The inner bag's OCTET STRING if the safe bag is of type `bag_nid` and the inner one of
/// `inner_type`.
fn octets_of(bag: *const PKCS12_SAFEBAG, bag_nid: c_int, inner_type: c_int) -> *const ASN1_STRING {
    // SAFETY: NULL or a live safe bag.
    let Some(b) = (unsafe { bag_of(bag) }) else {
        return ptr::null();
    };
    if nid(b) != bag_nid {
        return ptr::null();
    }
    match inner(b) {
        Some(i) if inner_nid(i) == inner_type => i.value.cast(),
        _ => ptr::null(),
    }
}

ffi_export! {
    /// A new certificate decoded from a certificate bag, or NULL.
    ///
    /// # Safety
    /// `bag` is NULL or a live safe bag.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_get1_cert(bag: *const PKCS12_SAFEBAG) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        let os = octets_of(bag, NID_certBag, NID_x509Certificate);
        if os.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let it = unsafe { X509_it() };
        // SAFETY: the bag's string.
        unsafe { ASN1_item_unpack(os, it) }.cast()
    }
}

ffi_export! {
    /// A new CRL decoded from a CRL bag, or NULL.
    ///
    /// # Safety
    /// `bag` is NULL or a live safe bag.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_get1_crl(bag: *const PKCS12_SAFEBAG) -> *mut X509_CRL
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        let os = octets_of(bag, NID_crlBag, NID_x509Crl);
        if os.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let it = unsafe { X509_CRL_it() };
        // SAFETY: the bag's string.
        unsafe { ASN1_item_unpack(os, it) }.cast()
    }
}

ffi_export! {
    /// A new certificate decoded from a certificate bag in a library context, or NULL.
    ///
    /// # Safety
    /// `bag` is NULL or a live safe bag; `libctx` NULL or live; `propq` NULL or a C string.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_get1_cert_ex(bag: *const PKCS12_SAFEBAG, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        let os = octets_of(bag, NID_certBag, NID_x509Certificate);
        if os.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let it = unsafe { X509_it() };
        // SAFETY: the bag's string; the caller's context and properties.
        let ret = unsafe { ASN1_item_unpack_ex(os, it, libctx, propq) }.cast::<X509>();
        // SAFETY: the new certificate, or NULL.
        if let Some(c) = unsafe { cert_of(ret) }
            // SAFETY: its slots; the caller's properties.
            && !unsafe { set0_libctx(&mut c.libctx, &mut c.propq, libctx, propq) }
        {
            // SAFETY: the certificate made here.
            unsafe { X509_free(ret) };
            return ptr::null_mut();
        }
        ret
    }
}

ffi_export! {
    /// A new CRL decoded from a CRL bag in a library context, or NULL.
    ///
    /// # Safety
    /// `bag` is NULL or a live safe bag; `libctx` NULL or live; `propq` NULL or a C string.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_get1_crl_ex(bag: *const PKCS12_SAFEBAG, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut X509_CRL
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        let os = octets_of(bag, NID_crlBag, NID_x509Crl);
        if os.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let it = unsafe { X509_CRL_it() };
        // SAFETY: the bag's string; the caller's context and properties.
        let ret = unsafe { ASN1_item_unpack_ex(os, it, libctx, propq) }.cast::<X509_CRL>();
        // SAFETY: the new CRL, or NULL.
        if let Some(c) = unsafe { crl_of(ret) }
            // SAFETY: its slots; the caller's properties.
            && !unsafe { set0_libctx(&mut c.libctx, &mut c.propq, libctx, propq) }
        {
            // SAFETY: the CRL made here.
            unsafe { X509_CRL_free(ret) };
            return ptr::null_mut();
        }
        ret
    }
}

/// The bag's attributes' slot.
fn attrs_slot(b: &mut SafeBag) -> *mut *mut stack_st_X509_ATTRIBUTE {
    (&raw mut b.attrib).cast()
}

/// Adds an attribute to the bag: 1, or 0.
///
/// # Safety
/// `bag` is NULL or a live safe bag; `bytes` holds `len` octets (as `type_` takes them).
unsafe fn add_attr(
    bag: *mut PKCS12_SAFEBAG,
    nid: c_int,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(b) = (unsafe { bag_of(bag) }) else {
        return 0;
    };
    // SAFETY: the bag's attributes; the caller's value.
    c_int::from(
        !unsafe { X509at_add1_attr_by_NID(attrs_slot(b), nid, type_, bytes, len) }.is_null(),
    )
}

ffi_export! {
    /// Adds a local key identifier: 1, or 0.
    ///
    /// # Safety
    /// `bag` is a live safe bag; `name` holds `namelen` octets.
    pub unsafe extern "C" fn PKCS12_add_localkeyid(bag: *mut PKCS12_SAFEBAG, name: *mut c_uchar, namelen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { add_attr(bag, NID_localKeyID, V_ASN1_OCTET_STRING, name, namelen) }
    }
}

ffi_export! {
    /// Adds a friendly name from ASCII: 1, or 0.
    ///
    /// # Safety
    /// `bag` is a live safe bag; `name` holds `namelen` characters (a C string if -1).
    pub unsafe extern "C" fn PKCS12_add_friendlyname_asc(bag: *mut PKCS12_SAFEBAG, name: *const c_char, namelen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { add_attr(bag, NID_friendlyName, MBSTRING_ASC, name.cast(), namelen) }
    }
}

ffi_export! {
    /// Adds a friendly name from UTF-8: 1, or 0.
    ///
    /// # Safety
    /// `bag` is a live safe bag; `name` holds `namelen` octets (a C string if -1).
    pub unsafe extern "C" fn PKCS12_add_friendlyname_utf8(bag: *mut PKCS12_SAFEBAG, name: *const c_char, namelen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { add_attr(bag, NID_friendlyName, MBSTRING_UTF8, name.cast(), namelen) }
    }
}

ffi_export! {
    /// Adds a friendly name from big-endian UTF-16: 1, or 0.
    ///
    /// # Safety
    /// `bag` is a live safe bag; `name` holds `namelen` octets.
    pub unsafe extern "C" fn PKCS12_add_friendlyname_uni(bag: *mut PKCS12_SAFEBAG, name: *const c_uchar, namelen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { add_attr(bag, NID_friendlyName, MBSTRING_BMP, name, namelen) }
    }
}

ffi_export! {
    /// Adds a Microsoft CSP name from ASCII: 1, or 0.
    ///
    /// # Safety
    /// `bag` is a live safe bag; `name` holds `namelen` characters (a C string if -1).
    pub unsafe extern "C" fn PKCS12_add_CSPName_asc(bag: *mut PKCS12_SAFEBAG, name: *const c_char, namelen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { add_attr(bag, NID_ms_csp_name, MBSTRING_ASC, name.cast(), namelen) }
    }
}

ffi_export! {
    /// Adds an attribute by NID: 1, or 0.
    ///
    /// # Safety
    /// `bag` is a live safe bag; `bytes` holds `len` octets (as `type_` takes them).
    pub unsafe extern "C" fn PKCS12_add1_attr_by_NID(bag: *mut PKCS12_SAFEBAG, nid: c_int, type_: c_int, bytes: *const c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { add_attr(bag, nid, type_, bytes, len) }
    }
}

ffi_export! {
    /// Adds an attribute by name or OID: 1, or 0.
    ///
    /// # Safety
    /// `bag` is a live safe bag; `attrname` a C string; `bytes` holds `len` octets.
    pub unsafe extern "C" fn PKCS12_add1_attr_by_txt(bag: *mut PKCS12_SAFEBAG, attrname: *const c_char, type_: c_int, bytes: *const c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { bag_of(bag) }) else { return 0 };
        // SAFETY: the bag's attributes; the caller's name and value.
        c_int::from(!unsafe { X509at_add1_attr_by_txt(attrs_slot(b), attrname, type_, bytes, len) }.is_null())
    }
}

ffi_export! {
    /// The first value of the first attribute `attr_nid` in the list, or NULL.
    ///
    /// # Safety
    /// `attrs` is NULL or a live list.
    pub unsafe extern "C" fn PKCS12_get_attr_gen(attrs: *const stack_st_X509_ATTRIBUTE, attr_nid: c_int) -> *mut ASN1_TYPE
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let i = unsafe { X509at_get_attr_by_NID(attrs, attr_nid, -1) };
        if i < 0 {
            return ptr::null_mut();
        }
        // SAFETY: as above; an index within it.
        let a = unsafe { X509at_get_attr(attrs, i) };
        // SAFETY: the attribute.
        unsafe { X509_ATTRIBUTE_get0_type(a, 0) }
    }
}

ffi_export! {
    /// The bag's attribute `attr_nid`'s first value, or NULL.
    ///
    /// # Safety
    /// `bag` is NULL or a live safe bag.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_get0_attr(bag: *const PKCS12_SAFEBAG, attr_nid: c_int) -> *const ASN1_TYPE
    where failure = ptr::null(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { bag_of(bag) }) else { return ptr::null() };
        // SAFETY: its attributes, or NULL.
        unsafe { PKCS12_get_attr_gen(b.attrib.cast(), attr_nid) }
    }
}

ffi_export! {
    /// The bag's attribute `attr_nid`'s first value, or NULL (deprecated).
    ///
    /// # Safety
    /// `bag` is NULL or a live safe bag.
    pub unsafe extern "C" fn PKCS12_get_attr(bag: *const PKCS12_SAFEBAG, attr_nid: c_int) -> *mut ASN1_TYPE
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS12_SAFEBAG_get0_attr(bag, attr_nid) }.cast_mut()
    }
}

ffi_export! {
    /// The bag's friendly name (a BMPString) as a new UTF-8 C string, or NULL.
    ///
    /// # Safety
    /// `bag` is NULL or a live safe bag.
    pub unsafe extern "C" fn PKCS12_get_friendlyname(bag: *mut PKCS12_SAFEBAG) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let t = unsafe { PKCS12_SAFEBAG_get0_attr(bag, NID_friendlyName) };
        // SAFETY: the attribute's value, or NULL.
        let Some(t) = (unsafe { t.as_ref() }) else { return ptr::null_mut() };
        if t.type_ != V_ASN1_BMPSTRING {
            return ptr::null_mut();
        }
        // SAFETY: a BMPString's value.
        let s = unsafe { t.value.bmpstring };
        // SAFETY: the string, NULL or live.
        let Some(s) = (unsafe { s.as_ref() }) else { return ptr::null_mut() };
        // SAFETY: its octets.
        unsafe { super::OPENSSL_uni2utf8(s.data, s.length) }
    }
}

ffi_export! {
    /// The bag's attributes, or NULL.
    ///
    /// # Safety
    /// `bag` is NULL or a live safe bag.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_get0_attrs(bag: *const PKCS12_SAFEBAG) -> *const stack_st_X509_ATTRIBUTE
    where failure = ptr::null(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { bag_of(bag) }.map_or(ptr::null(), |b| b.attrib.cast_const().cast())
    }
}

ffi_export! {
    /// Replaces the bag's attributes with `attrs`, which it takes (freeing the old list but
    /// not its attributes, as OpenSSL does).
    ///
    /// # Safety
    /// `bag` is NULL or a live safe bag; `attrs` NULL or a live list.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_set0_attrs(bag: *mut PKCS12_SAFEBAG, attrs: *mut stack_st_X509_ATTRIBUTE)
    where failure = (), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { bag_of(bag) }) else { return };
        if b.attrib.cast() != attrs {
            // SAFETY: the bag's own list, or NULL.
            unsafe { OPENSSL_sk_free(b.attrib.cast()) };
        }
        b.attrib = attrs.cast();
    }
}
