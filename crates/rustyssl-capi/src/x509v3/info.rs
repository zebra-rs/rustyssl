//! The information access extensions (`v3_info.c`): the authority's and subject's
//! information access, SEQUENCEs of `ACCESS_DESCRIPTION` (an access method and a location),
//! listed as `method - type:value` and made from `method;type:value`.

use core::ffi::{CStr, c_int, c_void};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ACCESS_DESCRIPTION, ASN1_ITEM, ASN1_ITYPE_PRIMITIVE, ASN1_TFLG_SEQUENCE_OF,
    AUTHORITY_INFO_ACCESS, BIO, CONF_VALUE, ERR_LIB_ASN1, ERR_LIB_X509V3, ERR_R_ASN1_LIB,
    ERR_R_CRYPTO_LIB, NID_info_access, NID_sinfo_access, X509V3_CTX, X509V3_EXT_METHOD,
    X509V3_EXT_MULTILINE, X509V3_R_BAD_OBJECT, X509V3_R_INVALID_SYNTAX, stack_st_CONF_VALUE,
};

use super::X509V3_conf_free;
use super::genn::GENERAL_NAME_it;
use super::registry::{Method, method};
use super::san::{i2v_GENERAL_NAME, v2i_GENERAL_NAME_ex};
use crate::asn1::tpl::items::{ASN1_OBJECT_it, d2i, i2d, new_free};
use crate::asn1::tpl::statics::{Templates, sequence};
use crate::asn1::tpl::{Template, item, item_fns, template, template_at};
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::objects::{OBJ_txt2obj, i2a_ASN1_OBJECT, i2t_ASN1_OBJECT};
use crate::stack::{
    OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
};

static AD_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(ACCESS_DESCRIPTION, method),
        c"method",
        ASN1_OBJECT_it,
    ),
    template_at(
        0,
        0,
        offset_of!(ACCESS_DESCRIPTION, location),
        c"location",
        GENERAL_NAME_it,
    ),
]);

item_fns! {
    /// AccessDescription: SEQUENCE { accessMethod OBJECT IDENTIFIER, accessLocation GeneralName }.
    pub unsafe extern "C" fn ACCESS_DESCRIPTION_it = sequence::<ACCESS_DESCRIPTION, 2>(&AD_TT, None, c"ACCESS_DESCRIPTION");
}

new_free! {
    pub unsafe extern "C" fn ACCESS_DESCRIPTION_new, pub unsafe extern "C" fn ACCESS_DESCRIPTION_free(ACCESS_DESCRIPTION) = ACCESS_DESCRIPTION_it;
}

i2d! {
    /// Encodes an AccessDescription.
    pub unsafe extern "C" fn i2d_ACCESS_DESCRIPTION(ACCESS_DESCRIPTION) = ACCESS_DESCRIPTION_it;
}

d2i! {
    /// Decodes an AccessDescription (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ACCESS_DESCRIPTION(ACCESS_DESCRIPTION) = ACCESS_DESCRIPTION_it;
}

static AIA_T: Template = template(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    c"GeneralNames",
    ACCESS_DESCRIPTION_it,
);

item_fns! {
    /// AuthorityInfoAccessSyntax: SEQUENCE OF AccessDescription.
    pub unsafe extern "C" fn AUTHORITY_INFO_ACCESS_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const AIA_T.0, 0, ptr::null(), 0, c"AUTHORITY_INFO_ACCESS");
}

new_free! {
    pub unsafe extern "C" fn AUTHORITY_INFO_ACCESS_new, pub unsafe extern "C" fn AUTHORITY_INFO_ACCESS_free(AUTHORITY_INFO_ACCESS) = AUTHORITY_INFO_ACCESS_it;
}

i2d! {
    /// Encodes an AuthorityInfoAccessSyntax.
    pub unsafe extern "C" fn i2d_AUTHORITY_INFO_ACCESS(AUTHORITY_INFO_ACCESS) = AUTHORITY_INFO_ACCESS_it;
}

d2i! {
    /// Decodes an AuthorityInfoAccessSyntax (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_AUTHORITY_INFO_ACCESS(AUTHORITY_INFO_ACCESS) = AUTHORITY_INFO_ACCESS_it;
}

/// `X509V3_conf_free` as a stack's free function.
unsafe extern "C" fn free_conf(c: *mut c_void) {
    // SAFETY: a `CONF_VALUE` of the stack, which the stack owned.
    unsafe { X509V3_conf_free(c.cast()) };
}

/// `ACCESS_DESCRIPTION_free` as a stack's free function.
unsafe extern "C" fn free_ad(a: *mut c_void) {
    // SAFETY: a description of the stack, which the stack owned.
    unsafe { ACCESS_DESCRIPTION_free(a.cast()) };
}

ffi_callback! {
    /// `i2v_AUTHORITY_INFO_ACCESS`: each location (`i2v_GENERAL_NAME`), its name prefixed with
    /// the method (`method - `). As OpenSSL's, the `i`th entry of the list is the one renamed.
    ///
    /// # Safety
    /// `ext` is a live stack of descriptions; `ret` is NULL or a live stack.
    pub(crate) unsafe extern "C" fn aia_i2v(method: *const X509V3_EXT_METHOD, ext: *mut c_void, ret: *mut stack_st_CONF_VALUE) -> *mut stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        let mut tret = ret;
        let fail = |tret: *mut stack_st_CONF_VALUE| {
            if ret.is_null() && !tret.is_null() {
                // SAFETY: the list made here, with its entries.
                unsafe { OPENSSL_sk_pop_free(tret.cast(), Some(free_conf)) };
            }
            ptr::null_mut()
        };
        // SAFETY: the caller's stack.
        let n = unsafe { OPENSSL_sk_num(ext.cast()) };
        for i in 0..n {
            // SAFETY: an index within the stack; a description.
            let Some(desc) = (unsafe { super::item_at::<ACCESS_DESCRIPTION>(ext.cast(), i) }) else { continue };
            // SAFETY: its location; the list.
            let tmp = unsafe { i2v_GENERAL_NAME(method.cast_mut(), desc.location, tret) };
            if tmp.is_null() {
                err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, "i2v_AUTHORITY_INFO_ACCESS");
                return fail(tret);
            }
            tret = tmp;
            // SAFETY: an index within the list.
            let vtmp = unsafe { OPENSSL_sk_value(tret.cast(), i) }.cast::<CONF_VALUE>();
            // SAFETY: an entry of the list.
            let Some(v) = (unsafe { vtmp.as_mut() }) else { return fail(tret) };
            let mut obj = [0 as core::ffi::c_char; 80];
            // SAFETY: room for 80 octets; the method's object.
            unsafe { i2t_ASN1_OBJECT(obj.as_mut_ptr(), 80, desc.method) };
            // SAFETY: NUL-terminated.
            let mut name = unsafe { CStr::from_ptr(obj.as_ptr()) }.to_bytes().to_vec();
            name.extend_from_slice(b" - ");
            if !v.name.is_null() {
                // SAFETY: the entry's name.
                name.extend_from_slice(unsafe { CStr::from_ptr(v.name) }.to_bytes());
            }
            let ntmp = crate::conf::c_dup(&name);
            if ntmp.is_null() {
                return fail(tret);
            }
            // SAFETY: the entry's old name.
            unsafe { mem::release(v.name.cast()) };
            v.name = ntmp;
        }
        if ret.is_null() && tret.is_null() {
            // SAFETY: no preconditions.
            return unsafe { crate::stack::OPENSSL_sk_new_null() }.cast();
        }
        tret
    }
}

ffi_callback! {
    /// `v2i_AUTHORITY_INFO_ACCESS`: each `method;type` name with its value, or NULL
    /// (`X509V3_R_INVALID_SYNTAX` without `;`, `X509V3_R_BAD_OBJECT` for the method).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `nval` is NULL or a live stack of `CONF_VALUE`s.
    pub(crate) unsafe extern "C" fn aia_v2i(method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, nval: *mut stack_st_CONF_VALUE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        const F: &str = "v2i_AUTHORITY_INFO_ACCESS";
        // SAFETY: the caller's stack, or NULL.
        let num = unsafe { OPENSSL_sk_num(nval.cast()) };
        // SAFETY: no preconditions.
        let ainfo = unsafe { OPENSSL_sk_new_reserve(None, num) };
        if ainfo.is_null() {
            err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, F);
            return ptr::null_mut();
        }
        let fail = || {
            // SAFETY: the stack made above, with its descriptions.
            unsafe { OPENSSL_sk_pop_free(ainfo, Some(free_ad)) };
            ptr::null_mut()
        };
        for i in 0..num {
            // SAFETY: an index within the stack; a `CONF_VALUE`.
            let Some(cnf) = (unsafe { super::item_at::<CONF_VALUE>(nval.cast(), i) }) else { continue };
            // SAFETY: no preconditions.
            let acc = unsafe { ACCESS_DESCRIPTION_new() };
            if acc.is_null() {
                err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                return fail();
            }
            // SAFETY: the stack, with room reserved; the description, which it takes.
            unsafe { OPENSSL_sk_push(ainfo, acc.cast()) };
            // SAFETY: the value's name.
            let name = if cnf.name.is_null() { &[][..] } else { unsafe { CStr::from_ptr(cnf.name) }.to_bytes() };
            let Some(semi) = name.iter().position(|&c| c == b';') else {
                err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_SYNTAX, F);
                return fail();
            };
            let mut ctmp = CONF_VALUE {
                section: ptr::null_mut(),
                name: cnf.name.wrapping_add(semi.saturating_add(1)),
                value: cnf.value,
            };
            // SAFETY: the new description.
            let a = unsafe { &mut *acc };
            // SAFETY: its location; the caller's context; the value.
            if unsafe { v2i_GENERAL_NAME_ex(a.location, method, ctx, &raw mut ctmp, 0) }.is_null() {
                return fail();
            }
            let objtmp = crate::conf::c_dup(name.get(..semi).unwrap_or_default());
            if objtmp.is_null() {
                return fail();
            }
            // SAFETY: the method's name.
            a.method = unsafe { OBJ_txt2obj(objtmp, 0) };
            if a.method.is_null() {
                let mut data = b"value=".to_vec();
                data.extend_from_slice(name.get(..semi).unwrap_or_default());
                err::raise_with_bytes(ERR_LIB_X509V3, X509V3_R_BAD_OBJECT, F, &data);
                // SAFETY: made above.
                unsafe { mem::release(objtmp.cast()) };
                return fail();
            }
            // SAFETY: as above.
            unsafe { mem::release(objtmp.cast()) };
        }
        ainfo.cast()
    }
}

ffi_export! {
    /// Writes the description's method (`i2a_ASN1_OBJECT`) and returns 2, as OpenSSL's does.
    ///
    /// # Safety
    /// `bp` is a live BIO; `a` is a live description.
    pub unsafe extern "C" fn i2a_ACCESS_DESCRIPTION(bp: *mut BIO, a: *const ACCESS_DESCRIPTION) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { a.as_ref() }) else { return 0 };
        // SAFETY: the caller's BIO; its method.
        unsafe { i2a_ASN1_OBJECT(bp, d.method) };
        2
    }
}

const fn info(nid: c_int) -> Method {
    let mut m = method(nid, X509V3_EXT_MULTILINE);
    m.it = Some(AUTHORITY_INFO_ACCESS_it);
    m.i2v = Some(aia_i2v);
    m.v2i = Some(aia_v2i);
    Method(m)
}

pub(crate) static INFO: Method = info(NID_info_access);
pub(crate) static SINFO: Method = info(NID_sinfo_access);
