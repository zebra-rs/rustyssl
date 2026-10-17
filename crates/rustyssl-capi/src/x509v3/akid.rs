//! The authority key identifier (`v3_akid.c`, `v3_akeya.c`): the issuer's key identifier, or
//! its name and serial number, as `AUTHORITY_KEYID`; made from `keyid` and `issuer` (each
//! optionally `:always`), or `none`, with the issuer's certificate and key from the context.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_TFLG_IMPLICIT, ASN1_TFLG_OPTIONAL, ASN1_TFLG_SEQUENCE_OF, AUTHORITY_KEYID,
    CONF_VALUE, ERR_LIB_ASN1, ERR_LIB_X509V3, ERR_R_ASN1_LIB, ERR_R_CRYPTO_LIB,
    ERR_R_PASSED_NULL_PARAMETER, ERR_R_X509_LIB, GEN_DIRNAME, NID_authority_key_identifier,
    NID_subject_key_identifier, X509V3_CTX, X509V3_CTX_TEST, X509V3_EXT_METHOD,
    X509V3_EXT_MULTILINE, X509V3_R_BAD_VALUE, X509V3_R_NO_ISSUER_CERTIFICATE,
    X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS, X509V3_R_UNABLE_TO_GET_ISSUER_KEYID,
    X509V3_R_UNKNOWN_OPTION, X509V3_R_UNKNOWN_VALUE, stack_st_CONF_VALUE,
};

use super::genn::{GENERAL_NAME_free, GENERAL_NAME_it, GENERAL_NAME_new};
use super::registry::{Method, X509V3_EXT_d2i, method};
use super::san::i2v_GENERAL_NAMES;
use super::simple::pubkey_hash;
use super::{X509V3_add_value, X509V3_conf_free, i2s_ASN1_OCTET_STRING};
use crate::asn1::integer::ASN1_INTEGER_dup;
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_OCTET_STRING_free, ASN1_STRING_length};
use crate::asn1::tpl::items::{ASN1_INTEGER_it, ASN1_OCTET_STRING_it, d2i, i2d, new_free};
use crate::asn1::tpl::statics::{Templates, sequence};
use crate::asn1::tpl::{item_fns, template_at};
use crate::err;
use crate::ffi::ffi_callback;
use crate::mem;
use crate::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
};
use crate::x509::cert::{
    X509_check_private_key, X509_get_ext, X509_get_ext_by_NID, X509_get_issuer_name,
    X509_get0_serialNumber,
};
use crate::x509::name::{X509_NAME_dup, X509_NAME_free};
use crate::x509::pubkey::{X509_PUBKEY_free, X509_PUBKEY_set};

static AKID_TT: Templates<3> = Templates([
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(AUTHORITY_KEYID, keyid),
        c"keyid",
        ASN1_OCTET_STRING_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(AUTHORITY_KEYID, issuer),
        c"issuer",
        GENERAL_NAME_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        2,
        offset_of!(AUTHORITY_KEYID, serial),
        c"serial",
        ASN1_INTEGER_it,
    ),
]);

item_fns! {
    /// AuthorityKeyIdentifier: SEQUENCE { keyIdentifier [0] OPTIONAL, authorityCertIssuer [1]
    /// GeneralNames OPTIONAL, authorityCertSerialNumber [2] INTEGER OPTIONAL }.
    pub unsafe extern "C" fn AUTHORITY_KEYID_it = sequence::<AUTHORITY_KEYID, 3>(&AKID_TT, None, c"AUTHORITY_KEYID");
}

new_free! {
    pub unsafe extern "C" fn AUTHORITY_KEYID_new, pub unsafe extern "C" fn AUTHORITY_KEYID_free(AUTHORITY_KEYID) = AUTHORITY_KEYID_it;
}

i2d! {
    /// Encodes an AuthorityKeyIdentifier.
    pub unsafe extern "C" fn i2d_AUTHORITY_KEYID(AUTHORITY_KEYID) = AUTHORITY_KEYID_it;
}

d2i! {
    /// Decodes an AuthorityKeyIdentifier (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_AUTHORITY_KEYID(AUTHORITY_KEYID) = AUTHORITY_KEYID_it;
}

/// `X509V3_conf_free` as a stack's free function.
unsafe extern "C" fn free_conf(c: *mut c_void) {
    // SAFETY: a `CONF_VALUE` of the stack, which the stack owned.
    unsafe { X509V3_conf_free(c.cast()) };
}

ffi_callback! {
    /// `i2v_AUTHORITY_KEYID`: the key identifier in hex (named `keyid` when the issuer or the
    /// serial number follows), the issuer's names, and the serial number in hex (`serial`).
    ///
    /// # Safety
    /// `ext` is a live AuthorityKeyIdentifier; `extlist` is NULL or a live stack.
    pub(crate) unsafe extern "C" fn akid_i2v(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, extlist: *mut stack_st_CONF_VALUE) -> *mut stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        const F: &str = "i2v_AUTHORITY_KEYID";
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { ext.cast::<AUTHORITY_KEYID>().as_ref() }) else { return ptr::null_mut() };
        let orig = extlist;
        let mut list = extlist;
        let fail = |list: *mut stack_st_CONF_VALUE| {
            if orig.is_null() {
                // SAFETY: the list made here, with its entries.
                unsafe { OPENSSL_sk_pop_free(list.cast(), Some(free_conf)) };
            }
            ptr::null_mut()
        };
        if !a.keyid.is_null() {
            // SAFETY: the key identifier.
            let tmp = unsafe { i2s_ASN1_OCTET_STRING(ptr::null_mut(), a.keyid) };
            if tmp.is_null() {
                err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                return ptr::null_mut();
            }
            let name = if a.issuer.is_null() && a.serial.is_null() { ptr::null() } else { c"keyid".as_ptr() };
            // SAFETY: a static name; the text; the list.
            let ok = unsafe { X509V3_add_value(name, tmp, &raw mut list) } != 0;
            // SAFETY: made above.
            unsafe { mem::release(tmp.cast()) };
            if !ok {
                err::raise(ERR_LIB_X509V3, ERR_R_X509_LIB, F);
                return fail(list);
            }
        }
        if !a.issuer.is_null() {
            // SAFETY: the issuer's names; the list.
            let tmp = unsafe { i2v_GENERAL_NAMES(ptr::null_mut(), a.issuer, list) };
            if tmp.is_null() {
                err::raise(ERR_LIB_X509V3, ERR_R_X509_LIB, F);
                return fail(list);
            }
            list = tmp;
        }
        if !a.serial.is_null() {
            // SAFETY: the serial number, an INTEGER read as octets.
            let tmp = unsafe { i2s_ASN1_OCTET_STRING(ptr::null_mut(), a.serial) };
            if tmp.is_null() {
                err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                return fail(list);
            }
            // SAFETY: as above.
            let ok = unsafe { X509V3_add_value(c"serial".as_ptr(), tmp, &raw mut list) } != 0;
            // SAFETY: made above.
            unsafe { mem::release(tmp.cast()) };
            if !ok {
                return fail(list);
            }
        }
        list
    }
}

/// A C string's bytes, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a C string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) }.to_bytes())
}

ffi_callback! {
    /// `v2i_AUTHORITY_KEYID`: `keyid` (the issuer's subject key identifier, or the hash of the
    /// issuer key for a self-issued certificate) and `issuer` (its issuer name and serial
    /// number), each only if needed unless `:always`; `none` alone for an empty one.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `values` is NULL or a live stack of `CONF_VALUE`s.
    pub(crate) unsafe extern "C" fn akid_v2i(_method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, values: *mut stack_st_CONF_VALUE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        const F: &str = "v2i_AUTHORITY_KEYID";
        // SAFETY: no preconditions.
        let akeyid = unsafe { AUTHORITY_KEYID_new() };
        if akeyid.is_null() {
            return ptr::null_mut();
        }
        let fail = |extra: &dyn Fn()| {
            extra();
            // SAFETY: made above.
            unsafe { AUTHORITY_KEYID_free(akeyid) };
            ptr::null_mut()
        };
        // SAFETY: the caller's stack, or NULL.
        let n = unsafe { OPENSSL_sk_num(values.cast()) };
        let value_at = |i: c_int| {
            // SAFETY: an index within the stack; a `CONF_VALUE`.
            unsafe { super::item_at::<CONF_VALUE>(values.cast(), i) }.map(|v| &*v)
        };
        // SAFETY: the first value's name.
        if n == 1 && value_at(0).is_some_and(|c| unsafe { text(c.name) } == Some(b"none")) {
            return akeyid.cast();
        }
        let (mut keyid, mut issuer) = (0u8, 0u8);
        for i in 0..n {
            let Some(cnf) = value_at(i) else { continue };
            // SAFETY: its strings.
            let (name, value) = (unsafe { text(cnf.name) }, unsafe { text(cnf.value) });
            if let Some(v) = value
                && v != b"always"
            {
                let mut data = b"name=".to_vec();
                data.extend_from_slice(name.unwrap_or_default());
                data.extend_from_slice(b" option=");
                data.extend_from_slice(v);
                err::raise_with_bytes(ERR_LIB_X509V3, X509V3_R_UNKNOWN_OPTION, F, &data);
                return fail(&|| {});
            }
            let level = if value.is_some() { 2 } else { 1 };
            match name {
                Some(b"keyid") if keyid == 0 => keyid = level,
                Some(b"issuer") if issuer == 0 => issuer = level,
                Some(b"none" | b"keyid" | b"issuer") => {
                    let mut data = b"name=".to_vec();
                    data.extend_from_slice(name.unwrap_or_default());
                    err::raise_with_bytes(ERR_LIB_X509V3, X509V3_R_BAD_VALUE, F, &data);
                    return fail(&|| {});
                }
                _ => {
                    let mut data = b"name=".to_vec();
                    data.extend_from_slice(name.unwrap_or_default());
                    err::raise_with_bytes(ERR_LIB_X509V3, X509V3_R_UNKNOWN_VALUE, F, &data);
                    return fail(&|| {});
                }
            }
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx.as_ref() }) else {
            err::raise(ERR_LIB_X509V3, ERR_R_PASSED_NULL_PARAMETER, F);
            return fail(&|| {});
        };
        if c.flags & X509V3_CTX_TEST != 0 {
            return akeyid.cast();
        }
        let issuer_cert = c.issuer_cert;
        if issuer_cert.is_null() {
            err::raise(ERR_LIB_X509V3, X509V3_R_NO_ISSUER_CERTIFICATE, F);
            return fail(&|| {});
        }
        let same_issuer = c.subject_cert == c.issuer_cert;
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_set_mark() };
        let ss = if c.issuer_pkey.is_null() {
            same_issuer
        } else {
            // SAFETY: the context's certificate and key.
            (unsafe { X509_check_private_key(c.subject_cert, c.issuer_pkey) } != 0)
        };
        // SAFETY: as above.
        unsafe { crate::err::ERR_pop_to_mark() };
        let mut ikeyid = ptr::null_mut();
        if keyid == 2 || (keyid == 1 && !ss) {
            // SAFETY: the issuer's certificate.
            let i = unsafe { X509_get_ext_by_NID(issuer_cert, NID_subject_key_identifier, -1) };
            // SAFETY: as above.
            let ext = if i >= 0 { unsafe { X509_get_ext(issuer_cert, i) } } else { ptr::null_mut() };
            if !ext.is_null() && !(same_issuer && !ss) {
                // SAFETY: its extension.
                ikeyid = unsafe { X509V3_EXT_d2i(ext) }.cast::<rustyssl_abi::ASN1_OCTET_STRING>();
                if ikeyid.is_null() {
                    return fail(&|| {});
                }
                // SAFETY: the identifier.
                if unsafe { ASN1_STRING_length(ikeyid) } == 0 {
                    // SAFETY: decoded above.
                    unsafe { ASN1_OCTET_STRING_free(ikeyid) };
                    ikeyid = ptr::null_mut();
                }
            }
            if ikeyid.is_null() && same_issuer && !c.issuer_pkey.is_null() {
                let mut pubkey = ptr::null_mut();
                // SAFETY: a local slot; the context's key.
                if unsafe { X509_PUBKEY_set(&raw mut pubkey, c.issuer_pkey) } != 0 {
                    // SAFETY: the key's SubjectPublicKeyInfo.
                    ikeyid = unsafe { pubkey_hash(pubkey) };
                }
                // SAFETY: made above, or NULL.
                unsafe { X509_PUBKEY_free(pubkey) };
            }
            if keyid == 2 && ikeyid.is_null() {
                err::raise(ERR_LIB_X509V3, X509V3_R_UNABLE_TO_GET_ISSUER_KEYID, F);
                return fail(&|| {});
            }
        }
        let free_keyid = || {
            // SAFETY: made above, or NULL.
            unsafe { ASN1_OCTET_STRING_free(ikeyid) };
        };
        let (mut isname, mut serial) = (ptr::null_mut(), ptr::null_mut());
        if issuer == 2 || (issuer == 1 && !ss && ikeyid.is_null()) {
            // SAFETY: the issuer's certificate.
            let iname = unsafe { X509_get_issuer_name(issuer_cert) };
            // SAFETY: its issuer.
            isname = unsafe { X509_NAME_dup(iname) };
            // SAFETY: the issuer's certificate.
            let iserial = unsafe { X509_get0_serialNumber(issuer_cert) };
            // SAFETY: its serial number.
            serial = unsafe { ASN1_INTEGER_dup(iserial) };
            if isname.is_null() || serial.is_null() {
                err::raise(ERR_LIB_X509V3, X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS, F);
                return fail(&|| {
                    free_keyid();
                    // SAFETY: copied above, or NULL.
                    unsafe { X509_NAME_free(isname) };
                    // SAFETY: as above.
                    unsafe { ASN1_INTEGER_free(serial) };
                });
            }
        }
        let mut gens = ptr::null_mut();
        if !isname.is_null() {
            // SAFETY: no preconditions.
            gens = unsafe { OPENSSL_sk_new_null() };
            // SAFETY: as above.
            let gname = if gens.is_null() { ptr::null_mut() } else { unsafe { GENERAL_NAME_new() } };
            let cleanup = |gname| {
                free_keyid();
                // SAFETY: made above, or NULL.
                unsafe { OPENSSL_sk_free(gens) };
                // SAFETY: as above.
                unsafe { GENERAL_NAME_free(gname) };
                // SAFETY: as above.
                unsafe { X509_NAME_free(isname) };
                // SAFETY: as above.
                unsafe { ASN1_INTEGER_free(serial) };
            };
            if gname.is_null() {
                err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                return fail(&|| cleanup(gname));
            }
            // SAFETY: the stack; the name, which it takes.
            if unsafe { OPENSSL_sk_push(gens, gname.cast()) } == 0 {
                err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, F);
                return fail(&|| cleanup(gname));
            }
            // SAFETY: the new name.
            let g = unsafe { &mut *gname };
            g.type_ = GEN_DIRNAME;
            g.d.dirn = isname;
        }
        // SAFETY: made above.
        let a = unsafe { &mut *akeyid };
        a.issuer = gens.cast();
        a.serial = serial;
        a.keyid = ikeyid;
        akeyid.cast()
    }
}

pub(crate) static AKEY_ID: Method = Method({
    let mut m = method(NID_authority_key_identifier, X509V3_EXT_MULTILINE);
    m.it = Some(AUTHORITY_KEYID_it);
    m.i2v = Some(akid_i2v);
    m.v2i = Some(akid_v2i);
    m
});
