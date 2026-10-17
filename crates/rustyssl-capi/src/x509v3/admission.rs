//! The admission extension (`v3_admis.c`, Common PKI): who admitted the subject to a
//! profession, and its profession information (`ADMISSION_SYNTAX`, `ADMISSIONS`,
//! `PROFESSION_INFO`, `NAMING_AUTHORITY`), with their getters and setters, and printed.
//!
//! As OpenSSL's, a naming authority with no part makes the whole extension's printing fail, and
//! object identifiers print as their long name with the dotted form (cut at 127 characters).
//! The types are opaque in OpenSSL's headers, so their layouts are ours.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ADMISSION_SYNTAX, ADMISSIONS, ASN1_IA5STRING, ASN1_ITEM, ASN1_OBJECT, ASN1_OCTET_STRING,
    ASN1_PRINTABLESTRING, ASN1_STRING, ASN1_TFLG_EXPLICIT, ASN1_TFLG_OPTIONAL,
    ASN1_TFLG_SEQUENCE_OF, BIO, ERR_LIB_ASN1, ERR_LIB_X509V3, GENERAL_NAME, NAMING_AUTHORITY,
    NID_x509ExtAdmission, PROFESSION_INFO, PROFESSION_INFOS, X509V3_EXT_METHOD,
    stack_st_ADMISSIONS, stack_st_ASN1_OBJECT, stack_st_ASN1_STRING,
};

use super::genn::{GENERAL_NAME_free, GENERAL_NAME_it};
use super::item_at;
use super::registry::{Method, method};
use super::san::GENERAL_NAME_print;
use crate::asn1::string::{
    ASN1_IA5STRING_free, ASN1_OCTET_STRING_free, ASN1_PRINTABLESTRING_free, ASN1_STRING_free,
};
use crate::asn1::text::ASN1_STRING_print;
use crate::asn1::tpl::items::{
    ASN1_IA5STRING_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_it, ASN1_PRINTABLESTRING_it,
    DIRECTORYSTRING_it, d2i, i2d, new_free,
};
use crate::asn1::tpl::statics::{Templates, sequence};
use crate::asn1::tpl::{item_fns, template_at};
use crate::bio::BIO_write;
use crate::ffi::{ffi_callback, ffi_export};
use crate::objects::{ASN1_OBJECT_free, OBJ_nid2ln, OBJ_obj2nid, OBJ_obj2txt};
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value};

/// `NAMING_AUTHORITY`.
#[repr(C)]
pub(crate) struct NamingAuthority {
    id: *mut ASN1_OBJECT,
    url: *mut ASN1_IA5STRING,
    text: *mut ASN1_STRING,
}

/// `PROFESSION_INFO`.
#[repr(C)]
pub(crate) struct ProfessionInfo {
    naming_authority: *mut NAMING_AUTHORITY,
    items: *mut stack_st_ASN1_STRING,
    oids: *mut stack_st_ASN1_OBJECT,
    registration_number: *mut ASN1_PRINTABLESTRING,
    add_info: *mut ASN1_OCTET_STRING,
}

/// `ADMISSIONS`.
#[repr(C)]
pub(crate) struct Admissions {
    authority: *mut GENERAL_NAME,
    naming_authority: *mut NAMING_AUTHORITY,
    infos: *mut PROFESSION_INFOS,
}

/// `ADMISSION_SYNTAX`.
#[repr(C)]
pub(crate) struct AdmissionSyntax {
    authority: *mut GENERAL_NAME,
    contents: *mut stack_st_ADMISSIONS,
}

static NA_TT: Templates<3> = Templates([
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(NamingAuthority, id),
        c"namingAuthorityId",
        ASN1_OBJECT_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(NamingAuthority, url),
        c"namingAuthorityUrl",
        ASN1_IA5STRING_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(NamingAuthority, text),
        c"namingAuthorityText",
        DIRECTORYSTRING_it,
    ),
]);

item_fns! {
    /// NamingAuthority: SEQUENCE { namingAuthorityId OBJECT IDENTIFIER OPTIONAL,
    /// namingAuthorityUrl IA5String OPTIONAL, namingAuthorityText DirectoryString OPTIONAL }.
    pub unsafe extern "C" fn NAMING_AUTHORITY_it = sequence::<NamingAuthority, 3>(&NA_TT, None, c"NAMING_AUTHORITY");
}

static PI_TT: Templates<5> = Templates([
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(ProfessionInfo, naming_authority),
        c"namingAuthority",
        NAMING_AUTHORITY_it,
    ),
    template_at(
        ASN1_TFLG_SEQUENCE_OF,
        0,
        offset_of!(ProfessionInfo, items),
        c"professionItems",
        DIRECTORYSTRING_it,
    ),
    template_at(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(ProfessionInfo, oids),
        c"professionOIDs",
        ASN1_OBJECT_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(ProfessionInfo, registration_number),
        c"registrationNumber",
        ASN1_PRINTABLESTRING_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(ProfessionInfo, add_info),
        c"addProfessionInfo",
        ASN1_OCTET_STRING_it,
    ),
]);

item_fns! {
    /// ProfessionInfo: SEQUENCE { namingAuthority [0] EXPLICIT NamingAuthority OPTIONAL,
    /// professionItems SEQUENCE OF DirectoryString, professionOIDs SEQUENCE OF OBJECT
    /// IDENTIFIER OPTIONAL, registrationNumber PrintableString OPTIONAL, addProfessionInfo
    /// OCTET STRING OPTIONAL }.
    pub unsafe extern "C" fn PROFESSION_INFO_it = sequence::<ProfessionInfo, 5>(&PI_TT, None, c"PROFESSION_INFO");
}

static ADM_TT: Templates<3> = Templates([
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(Admissions, authority),
        c"admissionAuthority",
        GENERAL_NAME_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(Admissions, naming_authority),
        c"namingAuthority",
        NAMING_AUTHORITY_it,
    ),
    template_at(
        ASN1_TFLG_SEQUENCE_OF,
        0,
        offset_of!(Admissions, infos),
        c"professionInfos",
        PROFESSION_INFO_it,
    ),
]);

item_fns! {
    /// Admissions: SEQUENCE { admissionAuthority [0] EXPLICIT GeneralName OPTIONAL,
    /// namingAuthority [1] EXPLICIT NamingAuthority OPTIONAL, professionInfos SEQUENCE OF
    /// ProfessionInfo }.
    pub unsafe extern "C" fn ADMISSIONS_it = sequence::<Admissions, 3>(&ADM_TT, None, c"ADMISSIONS");
}

static AS_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(AdmissionSyntax, authority),
        c"admissionAuthority",
        GENERAL_NAME_it,
    ),
    template_at(
        ASN1_TFLG_SEQUENCE_OF,
        0,
        offset_of!(AdmissionSyntax, contents),
        c"contentsOfAdmissions",
        ADMISSIONS_it,
    ),
]);

item_fns! {
    /// AdmissionSyntax: SEQUENCE { admissionAuthority GeneralName OPTIONAL,
    /// contentsOfAdmissions SEQUENCE OF Admissions }.
    pub unsafe extern "C" fn ADMISSION_SYNTAX_it = sequence::<AdmissionSyntax, 2>(&AS_TT, None, c"ADMISSION_SYNTAX");
}

new_free! {
    pub unsafe extern "C" fn NAMING_AUTHORITY_new, pub unsafe extern "C" fn NAMING_AUTHORITY_free(NAMING_AUTHORITY) = NAMING_AUTHORITY_it;
}

i2d! {
    /// Encodes a NamingAuthority.
    pub unsafe extern "C" fn i2d_NAMING_AUTHORITY(NAMING_AUTHORITY) = NAMING_AUTHORITY_it;
}

d2i! {
    /// Decodes a NamingAuthority (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_NAMING_AUTHORITY(NAMING_AUTHORITY) = NAMING_AUTHORITY_it;
}

new_free! {
    pub unsafe extern "C" fn PROFESSION_INFO_new, pub unsafe extern "C" fn PROFESSION_INFO_free(PROFESSION_INFO) = PROFESSION_INFO_it;
}

i2d! {
    /// Encodes a ProfessionInfo.
    pub unsafe extern "C" fn i2d_PROFESSION_INFO(PROFESSION_INFO) = PROFESSION_INFO_it;
}

d2i! {
    /// Decodes a ProfessionInfo (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_PROFESSION_INFO(PROFESSION_INFO) = PROFESSION_INFO_it;
}

new_free! {
    pub unsafe extern "C" fn ADMISSIONS_new, pub unsafe extern "C" fn ADMISSIONS_free(ADMISSIONS) = ADMISSIONS_it;
}

i2d! {
    /// Encodes Admissions.
    pub unsafe extern "C" fn i2d_ADMISSIONS(ADMISSIONS) = ADMISSIONS_it;
}

d2i! {
    /// Decodes Admissions (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ADMISSIONS(ADMISSIONS) = ADMISSIONS_it;
}

new_free! {
    pub unsafe extern "C" fn ADMISSION_SYNTAX_new, pub unsafe extern "C" fn ADMISSION_SYNTAX_free(ADMISSION_SYNTAX) = ADMISSION_SYNTAX_it;
}

i2d! {
    /// Encodes an AdmissionSyntax.
    pub unsafe extern "C" fn i2d_ADMISSION_SYNTAX(ADMISSION_SYNTAX) = ADMISSION_SYNTAX_it;
}

d2i! {
    /// Decodes an AdmissionSyntax (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ADMISSION_SYNTAX(ADMISSION_SYNTAX) = ADMISSION_SYNTAX_it;
}

/// `ADMISSIONS_free` as a stack's free function.
unsafe extern "C" fn free_admissions(p: *mut c_void) {
    // SAFETY: an element of the stack, which the stack owned.
    unsafe { ADMISSIONS_free(p.cast()) };
}

/// `PROFESSION_INFO_free` as a stack's free function.
unsafe extern "C" fn free_info(p: *mut c_void) {
    // SAFETY: as above.
    unsafe { PROFESSION_INFO_free(p.cast()) };
}

/// `ASN1_STRING_free` as a stack's free function.
unsafe extern "C" fn free_string(p: *mut c_void) {
    // SAFETY: as above.
    unsafe { ASN1_STRING_free(p.cast()) };
}

/// `ASN1_OBJECT_free` as a stack's free function.
unsafe extern "C" fn free_object(p: *mut c_void) {
    // SAFETY: as above.
    unsafe { ASN1_OBJECT_free(p.cast()) };
}

/// Writes `s` to the BIO: whether it went (`BIO_printf(...) > 0`).
///
/// # Safety
/// `out` is a live BIO.
unsafe fn puts(out: *mut BIO, s: &[u8]) -> bool {
    let n = c_int::try_from(s.len()).unwrap_or(c_int::MAX);
    // SAFETY: the caller's BIO; the octets.
    (unsafe { BIO_write(out, s.as_ptr().cast(), n) }) > 0
}

/// `%*s` then `s` in one write, as one `BIO_printf` does: whether it went.
///
/// # Safety
/// `out` is a live BIO.
unsafe fn line(out: *mut BIO, ind: c_int, s: &[u8]) -> bool {
    let mut v = vec![b' '; usize::try_from(ind).unwrap_or(0)];
    v.extend_from_slice(s);
    // SAFETY: the caller's guarantee.
    unsafe { puts(out, &v) }
}

/// An object as `i2r_ADMISSION_SYNTAX` prints it: `long name (dotted)`, or the dotted form
/// alone, through a 128-octet buffer.
///
/// # Safety
/// `obj` is a live object.
unsafe fn object_text(obj: *const ASN1_OBJECT) -> Vec<u8> {
    // SAFETY: the caller's object.
    let nid = unsafe { OBJ_obj2nid(obj) };
    // SAFETY: no preconditions.
    let ln = unsafe { OBJ_nid2ln(nid) };
    let mut buf = [0u8; 128];
    let n = c_int::try_from(buf.len()).unwrap_or(0);
    // SAFETY: a buffer of `n` octets; the object.
    unsafe { OBJ_obj2txt(buf.as_mut_ptr().cast::<c_char>(), n, obj, 1) };
    let dotted: Vec<u8> = buf.iter().copied().take_while(|&c| c != 0).collect();
    if ln.is_null() {
        return dotted;
    }
    // SAFETY: a static C string.
    let mut v = unsafe { CStr::from_ptr(ln) }.to_bytes().to_vec();
    v.extend_from_slice(b" (");
    v.extend_from_slice(&dotted);
    v.push(b')');
    v
}

/// `label`, the string, and a newline: whether they went.
///
/// # Safety
/// `out` is a live BIO; `s` is a live string.
unsafe fn string_line(out: *mut BIO, ind: c_int, label: &[u8], s: *const ASN1_STRING) -> bool {
    // SAFETY: the caller's guarantee.
    (unsafe { line(out, ind, label) })
        // SAFETY: as above.
        && unsafe { ASN1_STRING_print(out, s) } > 0
        // SAFETY: as above.
        && unsafe { puts(out, b"\n") }
}

/// `i2r_NAMING_AUTHORITY`: whether it printed (not if it has no part).
///
/// # Safety
/// `out` is a live BIO; `na` is NULL or a live naming authority.
unsafe fn naming_authority_i2r(na: *const NAMING_AUTHORITY, out: *mut BIO, ind: c_int) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(n) = (unsafe { na.cast::<NamingAuthority>().as_ref() }) else {
        return false;
    };
    if n.id.is_null() && n.text.is_null() && n.url.is_null() {
        return false;
    }
    // SAFETY: as above.
    if !unsafe { line(out, ind, b"namingAuthority:\n") } {
        return false;
    }
    if !n.id.is_null() {
        // SAFETY: as above.
        if !unsafe { line(out, ind, b"  namingAuthorityId: ") } {
            return false;
        }
        // SAFETY: its identifier.
        let mut t = unsafe { object_text(n.id) };
        t.push(b'\n');
        // SAFETY: as above.
        if !unsafe { puts(out, &t) } {
            return false;
        }
    }
    // SAFETY: as above; its text.
    if !n.text.is_null() && !unsafe { string_line(out, ind, b"  namingAuthorityText: ", n.text) } {
        return false;
    }
    // SAFETY: as above; its URL.
    if !n.url.is_null() && !unsafe { string_line(out, ind, b"  namingAuthorityUrl: ", n.url) } {
        return false;
    }
    true
}

/// `label`, then the name on a line of its own after `pad`: whether they went.
///
/// # Safety
/// `out` is a live BIO; `g` is a live name.
unsafe fn name_lines(
    out: *mut BIO,
    ind: c_int,
    label: &[u8],
    pad: &[u8],
    g: *mut GENERAL_NAME,
) -> bool {
    // SAFETY: the caller's guarantee.
    (unsafe { line(out, ind, label) })
        // SAFETY: as above.
        && unsafe { line(out, ind, pad) }
        // SAFETY: as above.
        && unsafe { GENERAL_NAME_print(out, g) } > 0
        // SAFETY: as above.
        && unsafe { puts(out, b"\n") }
}

/// A profession information entry, for [`admission_i2r`].
///
/// # Safety
/// `out` is a live BIO.
unsafe fn info_i2r(p: &ProfessionInfo, j: c_int, out: *mut BIO, ind: c_int) -> bool {
    let head = format!("  Profession Info Entry {}:\n", j.wrapping_add(1));
    // SAFETY: the caller's BIO.
    if !unsafe { line(out, ind, head.as_bytes()) } {
        return false;
    }
    if !p.registration_number.is_null()
        // SAFETY: as above; its registration number.
        && !unsafe { string_line(out, ind, b"    registrationNumber: ", p.registration_number) }
    {
        return false;
    }
    if !p.naming_authority.is_null()
        // SAFETY: as above; its naming authority.
        && !unsafe { naming_authority_i2r(p.naming_authority, out, ind.saturating_add(4)) }
    {
        return false;
    }
    if !p.items.is_null() {
        // SAFETY: as above.
        if !unsafe { line(out, ind, b"    Info Entries:\n") } {
            return false;
        }
        // SAFETY: its items.
        for k in 0..unsafe { OPENSSL_sk_num(p.items.cast()) } {
            // SAFETY: an index within them.
            let s = unsafe { OPENSSL_sk_value(p.items.cast(), k) }.cast::<ASN1_STRING>();
            // SAFETY: as above; a string of them.
            if !unsafe { string_line(out, ind, b"      ", s) } {
                return false;
            }
        }
    }
    if !p.oids.is_null() {
        // SAFETY: as above.
        if !unsafe { line(out, ind, b"    Profession OIDs:\n") } {
            return false;
        }
        // SAFETY: its identifiers.
        for k in 0..unsafe { OPENSSL_sk_num(p.oids.cast()) } {
            // SAFETY: an index within them.
            let o = unsafe { OPENSSL_sk_value(p.oids.cast(), k) }.cast::<ASN1_OBJECT>();
            // SAFETY: an identifier of them.
            let mut t = unsafe { object_text(o) };
            t.push(b'\n');
            // SAFETY: as above.
            if !unsafe { line(out, ind, b"      ") } || !unsafe { puts(out, &t) } {
                return false;
            }
        }
    }
    true
}

/// `i2r_ADMISSION_SYNTAX`'s body.
///
/// # Safety
/// `out` is a live BIO.
unsafe fn admission_i2r(a: &AdmissionSyntax, out: *mut BIO, ind: c_int) -> bool {
    if !a.authority.is_null()
        // SAFETY: the caller's BIO; the authority.
        && !unsafe { name_lines(out, ind, b"admissionAuthority:\n", b"  ", a.authority) }
    {
        return false;
    }
    // SAFETY: its admissions, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(a.contents.cast()) } {
        // SAFETY: an index within the admissions.
        let Some(e) = (unsafe { item_at::<Admissions>(a.contents.cast(), i) }) else {
            return false;
        };
        let head = format!("Entry {}:\n", i.wrapping_add(1));
        // SAFETY: as above.
        if !unsafe { line(out, ind, head.as_bytes()) } {
            return false;
        }
        if !e.authority.is_null()
            // SAFETY: as above; the entry's authority.
            && !unsafe { name_lines(out, ind, b"  admissionAuthority:\n", b"    ", e.authority) }
        {
            return false;
        }
        if !e.naming_authority.is_null()
            // SAFETY: as above; the entry's naming authority.
            && !unsafe { naming_authority_i2r(e.naming_authority, out, ind.saturating_add(2)) }
        {
            return false;
        }
        // SAFETY: its profession information, or NULL.
        for j in 0..unsafe { OPENSSL_sk_num(e.infos.cast()) } {
            // SAFETY: an index within it.
            let Some(p) = (unsafe { item_at::<ProfessionInfo>(e.infos.cast(), j) }) else {
                return false;
            };
            // SAFETY: as above.
            if !unsafe { info_i2r(p, j, out, ind) } {
                return false;
            }
        }
    }
    true
}

ffi_callback! {
    /// `i2r_ADMISSION_SYNTAX`: the admission authority, then each admission's authority,
    /// naming authority, and profession information.
    ///
    /// # Safety
    /// `ext` is a live admission syntax; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn admission_syntax_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { ext.cast::<AdmissionSyntax>().as_ref() }) else { return 0 };
        // SAFETY: as above.
        c_int::from(unsafe { admission_i2r(a, out, indent) })
    }
}

pub(crate) static ADMISSION: Method = Method({
    let mut m = method(NID_x509ExtAdmission, 0);
    m.it = Some(ADMISSION_SYNTAX_it);
    m.i2r = Some(admission_syntax_i2r);
    m
});

ffi_export! {
    /// Its identifier, which the naming authority keeps, or NULL.
    ///
    /// # Safety
    /// `n` is NULL or a live naming authority.
    pub unsafe extern "C" fn NAMING_AUTHORITY_get0_authorityId(n: *const NAMING_AUTHORITY) -> *const ASN1_OBJECT
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `NAMING_AUTHORITY` is a `NamingAuthority`.
        unsafe { n.cast::<NamingAuthority>().as_ref() }.map_or(ptr::null(), |s| s.id.cast_const())
    }
}

ffi_export! {
    /// Replaces its identifier (freeing the old) with `value`, which it takes.
    ///
    /// # Safety
    /// `n` is NULL or a live naming authority; `value` is NULL or one the caller gives up.
    pub unsafe extern "C" fn NAMING_AUTHORITY_set0_authorityId(n: *mut NAMING_AUTHORITY, value: *mut ASN1_OBJECT)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `NAMING_AUTHORITY` is a `NamingAuthority`.
        let Some(s) = (unsafe { n.cast::<NamingAuthority>().as_mut() }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { ASN1_OBJECT_free(s.id) };
        s.id = value;
    }
}

ffi_export! {
    /// Its URL, which the naming authority keeps, or NULL.
    ///
    /// # Safety
    /// `n` is NULL or a live naming authority.
    pub unsafe extern "C" fn NAMING_AUTHORITY_get0_authorityURL(n: *const NAMING_AUTHORITY) -> *const ASN1_IA5STRING
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `NAMING_AUTHORITY` is a `NamingAuthority`.
        unsafe { n.cast::<NamingAuthority>().as_ref() }.map_or(ptr::null(), |s| s.url.cast_const())
    }
}

ffi_export! {
    /// Replaces its URL (freeing the old) with `value`, which it takes.
    ///
    /// # Safety
    /// `n` is NULL or a live naming authority; `value` is NULL or one the caller gives up.
    pub unsafe extern "C" fn NAMING_AUTHORITY_set0_authorityURL(n: *mut NAMING_AUTHORITY, value: *mut ASN1_IA5STRING)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `NAMING_AUTHORITY` is a `NamingAuthority`.
        let Some(s) = (unsafe { n.cast::<NamingAuthority>().as_mut() }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { ASN1_IA5STRING_free(s.url) };
        s.url = value;
    }
}

ffi_export! {
    /// Its text, which the naming authority keeps, or NULL.
    ///
    /// # Safety
    /// `n` is NULL or a live naming authority.
    pub unsafe extern "C" fn NAMING_AUTHORITY_get0_authorityText(n: *const NAMING_AUTHORITY) -> *const ASN1_STRING
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `NAMING_AUTHORITY` is a `NamingAuthority`.
        unsafe { n.cast::<NamingAuthority>().as_ref() }.map_or(ptr::null(), |s| s.text.cast_const())
    }
}

ffi_export! {
    /// Replaces its text (freeing the old) with `value`, which it takes.
    ///
    /// # Safety
    /// `n` is NULL or a live naming authority; `value` is NULL or one the caller gives up.
    pub unsafe extern "C" fn NAMING_AUTHORITY_set0_authorityText(n: *mut NAMING_AUTHORITY, value: *mut ASN1_STRING)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `NAMING_AUTHORITY` is a `NamingAuthority`.
        let Some(s) = (unsafe { n.cast::<NamingAuthority>().as_mut() }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { ASN1_IA5STRING_free(s.text) };
        s.text = value;
    }
}

ffi_export! {
    /// Its admission authority, which the admission syntax keeps, or NULL.
    ///
    /// # Safety
    /// `as_` is NULL or a live admission syntax.
    pub unsafe extern "C" fn ADMISSION_SYNTAX_get0_admissionAuthority(as_: *const ADMISSION_SYNTAX) -> *const GENERAL_NAME
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `ADMISSION_SYNTAX` is a `AdmissionSyntax`.
        unsafe { as_.cast::<AdmissionSyntax>().as_ref() }.map_or(ptr::null(), |s| s.authority.cast_const())
    }
}

ffi_export! {
    /// Replaces its admission authority (freeing the old) with `value`, which it takes.
    ///
    /// # Safety
    /// `as_` is NULL or a live admission syntax; `value` is NULL or one the caller gives up.
    pub unsafe extern "C" fn ADMISSION_SYNTAX_set0_admissionAuthority(as_: *mut ADMISSION_SYNTAX, value: *mut GENERAL_NAME)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `ADMISSION_SYNTAX` is a `AdmissionSyntax`.
        let Some(s) = (unsafe { as_.cast::<AdmissionSyntax>().as_mut() }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { GENERAL_NAME_free(s.authority) };
        s.authority = value;
    }
}

ffi_export! {
    /// Its admissions, which the admission syntax keeps, or NULL.
    ///
    /// # Safety
    /// `as_` is NULL or a live admission syntax.
    pub unsafe extern "C" fn ADMISSION_SYNTAX_get0_contentsOfAdmissions(as_: *const ADMISSION_SYNTAX) -> *const stack_st_ADMISSIONS
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `ADMISSION_SYNTAX` is a `AdmissionSyntax`.
        unsafe { as_.cast::<AdmissionSyntax>().as_ref() }.map_or(ptr::null(), |s| s.contents.cast_const())
    }
}

ffi_export! {
    /// Replaces its admissions (freeing the old) with `value`, which it takes.
    ///
    /// # Safety
    /// `as_` is NULL or a live admission syntax; `value` is NULL or one the caller gives up.
    pub unsafe extern "C" fn ADMISSION_SYNTAX_set0_contentsOfAdmissions(as_: *mut ADMISSION_SYNTAX, value: *mut stack_st_ADMISSIONS)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `ADMISSION_SYNTAX` is a `AdmissionSyntax`.
        let Some(s) = (unsafe { as_.cast::<AdmissionSyntax>().as_mut() }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { OPENSSL_sk_pop_free(s.contents.cast(), Some(free_admissions)) };
        s.contents = value;
    }
}

ffi_export! {
    /// Its admission authority, which the admissions entry keeps, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live admissions entry.
    pub unsafe extern "C" fn ADMISSIONS_get0_admissionAuthority(a: *const ADMISSIONS) -> *const GENERAL_NAME
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `ADMISSIONS` is a `Admissions`.
        unsafe { a.cast::<Admissions>().as_ref() }.map_or(ptr::null(), |s| s.authority.cast_const())
    }
}

ffi_export! {
    /// Replaces its admission authority (freeing the old) with `value`, which it takes.
    ///
    /// # Safety
    /// `a` is NULL or a live admissions entry; `value` is NULL or one the caller gives up.
    pub unsafe extern "C" fn ADMISSIONS_set0_admissionAuthority(a: *mut ADMISSIONS, value: *mut GENERAL_NAME)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `ADMISSIONS` is a `Admissions`.
        let Some(s) = (unsafe { a.cast::<Admissions>().as_mut() }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { GENERAL_NAME_free(s.authority) };
        s.authority = value;
    }
}

ffi_export! {
    /// Its naming authority, which the admissions entry keeps, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live admissions entry.
    pub unsafe extern "C" fn ADMISSIONS_get0_namingAuthority(a: *const ADMISSIONS) -> *const NAMING_AUTHORITY
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `ADMISSIONS` is a `Admissions`.
        unsafe { a.cast::<Admissions>().as_ref() }.map_or(ptr::null(), |s| s.naming_authority.cast_const())
    }
}

ffi_export! {
    /// Replaces its naming authority (freeing the old) with `value`, which it takes.
    ///
    /// # Safety
    /// `a` is NULL or a live admissions entry; `value` is NULL or one the caller gives up.
    pub unsafe extern "C" fn ADMISSIONS_set0_namingAuthority(a: *mut ADMISSIONS, value: *mut NAMING_AUTHORITY)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `ADMISSIONS` is a `Admissions`.
        let Some(s) = (unsafe { a.cast::<Admissions>().as_mut() }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { NAMING_AUTHORITY_free(s.naming_authority) };
        s.naming_authority = value;
    }
}

ffi_export! {
    /// Its profession information, which the admissions entry keeps, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live admissions entry.
    pub unsafe extern "C" fn ADMISSIONS_get0_professionInfos(a: *const ADMISSIONS) -> *const PROFESSION_INFOS
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `ADMISSIONS` is a `Admissions`.
        unsafe { a.cast::<Admissions>().as_ref() }.map_or(ptr::null(), |s| s.infos.cast_const())
    }
}

ffi_export! {
    /// Replaces its profession information (freeing the old) with `value`, which it takes.
    ///
    /// # Safety
    /// `a` is NULL or a live admissions entry; `value` is NULL or one the caller gives up.
    pub unsafe extern "C" fn ADMISSIONS_set0_professionInfos(a: *mut ADMISSIONS, value: *mut PROFESSION_INFOS)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `ADMISSIONS` is a `Admissions`.
        let Some(s) = (unsafe { a.cast::<Admissions>().as_mut() }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { OPENSSL_sk_pop_free(s.infos.cast(), Some(free_info)) };
        s.infos = value;
    }
}

ffi_export! {
    /// Its additional information, which the profession information keeps, or NULL.
    ///
    /// # Safety
    /// `pi` is NULL or a live profession information.
    pub unsafe extern "C" fn PROFESSION_INFO_get0_addProfessionInfo(pi: *const PROFESSION_INFO) -> *const ASN1_OCTET_STRING
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `PROFESSION_INFO` is a `ProfessionInfo`.
        unsafe { pi.cast::<ProfessionInfo>().as_ref() }.map_or(ptr::null(), |s| s.add_info.cast_const())
    }
}

ffi_export! {
    /// Replaces its additional information (freeing the old) with `value`, which it takes.
    ///
    /// # Safety
    /// `pi` is NULL or a live profession information; `value` is NULL or one the caller gives up.
    pub unsafe extern "C" fn PROFESSION_INFO_set0_addProfessionInfo(pi: *mut PROFESSION_INFO, value: *mut ASN1_OCTET_STRING)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `PROFESSION_INFO` is a `ProfessionInfo`.
        let Some(s) = (unsafe { pi.cast::<ProfessionInfo>().as_mut() }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { ASN1_OCTET_STRING_free(s.add_info) };
        s.add_info = value;
    }
}

ffi_export! {
    /// Its naming authority, which the profession information keeps, or NULL.
    ///
    /// # Safety
    /// `pi` is NULL or a live profession information.
    pub unsafe extern "C" fn PROFESSION_INFO_get0_namingAuthority(pi: *const PROFESSION_INFO) -> *const NAMING_AUTHORITY
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `PROFESSION_INFO` is a `ProfessionInfo`.
        unsafe { pi.cast::<ProfessionInfo>().as_ref() }.map_or(ptr::null(), |s| s.naming_authority.cast_const())
    }
}

ffi_export! {
    /// Replaces its naming authority (freeing the old) with `value`, which it takes.
    ///
    /// # Safety
    /// `pi` is NULL or a live profession information; `value` is NULL or one the caller gives up.
    pub unsafe extern "C" fn PROFESSION_INFO_set0_namingAuthority(pi: *mut PROFESSION_INFO, value: *mut NAMING_AUTHORITY)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `PROFESSION_INFO` is a `ProfessionInfo`.
        let Some(s) = (unsafe { pi.cast::<ProfessionInfo>().as_mut() }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { NAMING_AUTHORITY_free(s.naming_authority) };
        s.naming_authority = value;
    }
}

ffi_export! {
    /// Its profession items, which the profession information keeps, or NULL.
    ///
    /// # Safety
    /// `pi` is NULL or a live profession information.
    pub unsafe extern "C" fn PROFESSION_INFO_get0_professionItems(pi: *const PROFESSION_INFO) -> *const stack_st_ASN1_STRING
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `PROFESSION_INFO` is a `ProfessionInfo`.
        unsafe { pi.cast::<ProfessionInfo>().as_ref() }.map_or(ptr::null(), |s| s.items.cast_const())
    }
}

ffi_export! {
    /// Replaces its profession items (freeing the old) with `value`, which it takes.
    ///
    /// # Safety
    /// `pi` is NULL or a live profession information; `value` is NULL or one the caller gives up.
    pub unsafe extern "C" fn PROFESSION_INFO_set0_professionItems(pi: *mut PROFESSION_INFO, value: *mut stack_st_ASN1_STRING)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `PROFESSION_INFO` is a `ProfessionInfo`.
        let Some(s) = (unsafe { pi.cast::<ProfessionInfo>().as_mut() }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { OPENSSL_sk_pop_free(s.items.cast(), Some(free_string)) };
        s.items = value;
    }
}

ffi_export! {
    /// Its profession identifiers, which the profession information keeps, or NULL.
    ///
    /// # Safety
    /// `pi` is NULL or a live profession information.
    pub unsafe extern "C" fn PROFESSION_INFO_get0_professionOIDs(pi: *const PROFESSION_INFO) -> *const stack_st_ASN1_OBJECT
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `PROFESSION_INFO` is a `ProfessionInfo`.
        unsafe { pi.cast::<ProfessionInfo>().as_ref() }.map_or(ptr::null(), |s| s.oids.cast_const())
    }
}

ffi_export! {
    /// Replaces its profession identifiers (freeing the old) with `value`, which it takes.
    ///
    /// # Safety
    /// `pi` is NULL or a live profession information; `value` is NULL or one the caller gives up.
    pub unsafe extern "C" fn PROFESSION_INFO_set0_professionOIDs(pi: *mut PROFESSION_INFO, value: *mut stack_st_ASN1_OBJECT)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `PROFESSION_INFO` is a `ProfessionInfo`.
        let Some(s) = (unsafe { pi.cast::<ProfessionInfo>().as_mut() }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { OPENSSL_sk_pop_free(s.oids.cast(), Some(free_object)) };
        s.oids = value;
    }
}

ffi_export! {
    /// Its registration number, which the profession information keeps, or NULL.
    ///
    /// # Safety
    /// `pi` is NULL or a live profession information.
    pub unsafe extern "C" fn PROFESSION_INFO_get0_registrationNumber(pi: *const PROFESSION_INFO) -> *const ASN1_PRINTABLESTRING
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `PROFESSION_INFO` is a `ProfessionInfo`.
        unsafe { pi.cast::<ProfessionInfo>().as_ref() }.map_or(ptr::null(), |s| s.registration_number.cast_const())
    }
}

ffi_export! {
    /// Replaces its registration number (freeing the old) with `value`, which it takes.
    ///
    /// # Safety
    /// `pi` is NULL or a live profession information; `value` is NULL or one the caller gives up.
    pub unsafe extern "C" fn PROFESSION_INFO_set0_registrationNumber(pi: *mut PROFESSION_INFO, value: *mut ASN1_PRINTABLESTRING)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee; a `PROFESSION_INFO` is a `ProfessionInfo`.
        let Some(s) = (unsafe { pi.cast::<ProfessionInfo>().as_mut() }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { ASN1_PRINTABLESTRING_free(s.registration_number) };
        s.registration_number = value;
    }
}
