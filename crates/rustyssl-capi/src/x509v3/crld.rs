//! CRL distribution points (`v3_crld.c`): the CRL distribution points and freshest CRL
//! extensions (SEQUENCEs of `DIST_POINT`), a CRL's issuing distribution point, the invalidity
//! date and hold instruction of a CRL entry, and the names they hold (`DIST_POINT_NAME`, a
//! full name or a name relative to the CRL issuer's).
//!
//! As OpenSSL's, distribution points are made from names (`URI:…`) or from sections
//! (`fullname`, `relativename`, `reasons`, `CRLissuer`), and printed with their reasons by
//! name. So is an attribute authority's issuing distribution point (an attribute certificate
//! extension), from a name or a section, its booleans printed only when true.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_ITEM, ASN1_ITYPE_PRIMITIVE, ASN1_OP_FREE_POST, ASN1_OP_NEW_POST,
    ASN1_TFLG_EXPLICIT, ASN1_TFLG_IMPLICIT, ASN1_TFLG_OPTIONAL, ASN1_TFLG_SEQUENCE_OF,
    ASN1_TFLG_SET_OF, ASN1_VALUE, BIO, BIT_STRING_BITNAME, CONF_VALUE, CRL_DIST_POINTS, DIST_POINT,
    DIST_POINT_NAME, ERR_LIB_ASN1, ERR_LIB_X509V3, ERR_R_ASN1_LIB, ERR_R_CRYPTO_LIB, GENERAL_NAMES,
    ISSUING_DIST_POINT, MBSTRING_ASC, NID_crl_distribution_points, NID_freshest_crl,
    NID_hold_instruction_code, NID_id_aa_issuing_distribution_point, NID_invalidity_date,
    NID_issuing_distribution_point, OSSL_AA_DIST_POINT, X509_NAME, X509V3_CTX, X509V3_EXT_METHOD,
    X509V3_EXT_MULTILINE, X509V3_R_DISTPOINT_ALREADY_SET, X509V3_R_INVALID_MULTIPLE_RDNS,
    X509V3_R_INVALID_NAME, X509V3_R_MISSING_VALUE, X509V3_R_SECTION_NOT_FOUND, XN_FLAG_ONELINE,
    stack_st_CONF_VALUE,
};

use super::ctx::{X509V3_NAME_from_section, X509V3_get_section, X509V3_section_free};
use super::genn::{GENERAL_NAME_free, GENERAL_NAME_it, GENERAL_NAMES_free, GENERAL_NAMES_new};
use super::registry::{Method, indent_to, method};
use super::san::{GENERAL_NAME_print, free_gen, v2i_GENERAL_NAME, v2i_GENERAL_NAMES};
use super::simple::{BitNames, add_error_name_value};
use super::{X509V3_conf_free, X509V3_get_value_bool, X509V3_parse_list};
use crate::asn1::bit_string::{ASN1_BIT_STRING_get_bit, ASN1_BIT_STRING_set_bit};
use crate::asn1::string::ASN1_BIT_STRING_new;
use crate::asn1::time::ASN1_GENERALIZEDTIME_print;
use crate::asn1::tpl::items::{
    ASN1_BIT_STRING_it, ASN1_FBOOLEAN_it, ASN1_GENERALIZEDTIME_it, ASN1_OBJECT_it,
    ASN1_TBOOLEAN_it, d2i, i2d, new_free,
};
use crate::asn1::tpl::statics::{Aux, Templates, aux, choice, sequence};
use crate::asn1::tpl::util::ASN1_item_dup;
use crate::asn1::tpl::{Template, item, item_fns, template, template_at};
use crate::bio::BIO_puts;
use crate::bio::print::BIO_printf;
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::objects::i2a_ASN1_OBJECT;
use crate::stack::{
    OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::x509::name::{
    Name, X509_NAME_ENTRY_it, X509_NAME_add_entry, X509_NAME_dup, X509_NAME_free, X509_NAME_new,
    X509_NAME_print_ex, entry_of, name_of,
};

// The items.

static DPN_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF,
        0,
        offset_of!(DIST_POINT_NAME, name),
        c"name.fullname",
        GENERAL_NAME_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF,
        1,
        offset_of!(DIST_POINT_NAME, name),
        c"name.relativename",
        X509_NAME_ENTRY_it,
    ),
]);

ffi_callback! {
    /// `dpn_cb`: a distribution point name's full name relative to its issuer (`dpname`)
    /// starts empty and is freed with it.
    ///
    /// # Safety
    /// `pval` holds NULL or a live distribution point name.
    pub(crate) unsafe extern "C" fn dpn_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, _exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let v = unsafe { pval.read() };
        // SAFETY: as above.
        let Some(d) = (unsafe { v.cast::<DIST_POINT_NAME>().as_mut() }) else { return 1 };
        match operation {
            ASN1_OP_NEW_POST => d.dpname = ptr::null_mut(),
            ASN1_OP_FREE_POST => {
                // SAFETY: its own, or NULL.
                unsafe { X509_NAME_free(d.dpname) };
                d.dpname = ptr::null_mut();
            }
            _ => {}
        }
        1
    }
}

static DPN_AUX: Aux = aux(dpn_cb);

item_fns! {
    /// DistributionPointName: CHOICE { fullName [0] GeneralNames, nameRelativeToCRLIssuer [1]
    /// RelativeDistinguishedName }, its selector the `type`.
    pub unsafe extern "C" fn DIST_POINT_NAME_it = choice::<DIST_POINT_NAME, 2>(&DPN_TT, offset_of!(DIST_POINT_NAME, type_), Some(&DPN_AUX), c"DIST_POINT_NAME");
}

new_free! {
    pub unsafe extern "C" fn DIST_POINT_NAME_new, pub unsafe extern "C" fn DIST_POINT_NAME_free(DIST_POINT_NAME) = DIST_POINT_NAME_it;
}

i2d! {
    /// Encodes a DistributionPointName.
    pub unsafe extern "C" fn i2d_DIST_POINT_NAME(DIST_POINT_NAME) = DIST_POINT_NAME_it;
}

d2i! {
    /// Decodes a DistributionPointName (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_DIST_POINT_NAME(DIST_POINT_NAME) = DIST_POINT_NAME_it;
}

ffi_export! {
    /// A copy of the name (through its encoding; without its full name relative to an issuer),
    /// or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live distribution point name.
    pub unsafe extern "C" fn DIST_POINT_NAME_dup(a: *const DIST_POINT_NAME) -> *mut DIST_POINT_NAME
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { DIST_POINT_NAME_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_dup(it, a.cast_mut().cast()) }.cast()
    }
}

static DP_TT: Templates<3> = Templates([
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(DIST_POINT, distpoint),
        c"distpoint",
        DIST_POINT_NAME_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(DIST_POINT, reasons),
        c"reasons",
        ASN1_BIT_STRING_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        2,
        offset_of!(DIST_POINT, CRLissuer),
        c"CRLissuer",
        GENERAL_NAME_it,
    ),
]);

item_fns! {
    /// DistributionPoint: SEQUENCE { distributionPoint [0] OPTIONAL, reasons [1] ReasonFlags
    /// OPTIONAL, cRLIssuer [2] GeneralNames OPTIONAL }.
    pub unsafe extern "C" fn DIST_POINT_it = sequence::<DIST_POINT, 3>(&DP_TT, None, c"DIST_POINT");
}

new_free! {
    pub unsafe extern "C" fn DIST_POINT_new, pub unsafe extern "C" fn DIST_POINT_free(DIST_POINT) = DIST_POINT_it;
}

i2d! {
    /// Encodes a DistributionPoint.
    pub unsafe extern "C" fn i2d_DIST_POINT(DIST_POINT) = DIST_POINT_it;
}

d2i! {
    /// Decodes a DistributionPoint (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_DIST_POINT(DIST_POINT) = DIST_POINT_it;
}

static CRLD_T: Template = template(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    c"CRLDistributionPoints",
    DIST_POINT_it,
);

item_fns! {
    /// CRLDistributionPoints: SEQUENCE OF DistributionPoint.
    pub unsafe extern "C" fn CRL_DIST_POINTS_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const CRLD_T.0, 0, ptr::null(), 0, c"CRL_DIST_POINTS");
}

new_free! {
    pub unsafe extern "C" fn CRL_DIST_POINTS_new, pub unsafe extern "C" fn CRL_DIST_POINTS_free(CRL_DIST_POINTS) = CRL_DIST_POINTS_it;
}

i2d! {
    /// Encodes CRLDistributionPoints.
    pub unsafe extern "C" fn i2d_CRL_DIST_POINTS(CRL_DIST_POINTS) = CRL_DIST_POINTS_it;
}

d2i! {
    /// Decodes CRLDistributionPoints (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_CRL_DIST_POINTS(CRL_DIST_POINTS) = CRL_DIST_POINTS_it;
}

static IDP_TT: Templates<6> = Templates([
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(ISSUING_DIST_POINT, distpoint),
        c"distpoint",
        DIST_POINT_NAME_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(ISSUING_DIST_POINT, onlyuser),
        c"onlyuser",
        ASN1_FBOOLEAN_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        2,
        offset_of!(ISSUING_DIST_POINT, onlyCA),
        c"onlyCA",
        ASN1_FBOOLEAN_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        3,
        offset_of!(ISSUING_DIST_POINT, onlysomereasons),
        c"onlysomereasons",
        ASN1_BIT_STRING_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        4,
        offset_of!(ISSUING_DIST_POINT, indirectCRL),
        c"indirectCRL",
        ASN1_FBOOLEAN_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        5,
        offset_of!(ISSUING_DIST_POINT, onlyattr),
        c"onlyattr",
        ASN1_FBOOLEAN_it,
    ),
]);

item_fns! {
    /// IssuingDistributionPoint.
    pub unsafe extern "C" fn ISSUING_DIST_POINT_it = sequence::<ISSUING_DIST_POINT, 6>(&IDP_TT, None, c"ISSUING_DIST_POINT");
}

new_free! {
    pub unsafe extern "C" fn ISSUING_DIST_POINT_new, pub unsafe extern "C" fn ISSUING_DIST_POINT_free(ISSUING_DIST_POINT) = ISSUING_DIST_POINT_it;
}

i2d! {
    /// Encodes an IssuingDistributionPoint.
    pub unsafe extern "C" fn i2d_ISSUING_DIST_POINT(ISSUING_DIST_POINT) = ISSUING_DIST_POINT_it;
}

d2i! {
    /// Decodes an IssuingDistributionPoint (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ISSUING_DIST_POINT(ISSUING_DIST_POINT) = ISSUING_DIST_POINT_it;
}

// Making them from text.

/// A C string's bytes, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a C string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) }.to_bytes())
}

/// `X509V3_conf_free` as a stack's free function.
unsafe extern "C" fn free_conf(c: *mut c_void) {
    // SAFETY: a `CONF_VALUE` of the stack, which the stack owned.
    unsafe { X509V3_conf_free(c.cast()) };
}

/// `gnames_from_sectname`: the names of a section (`@section`) or of a list.
///
/// # Safety
/// `ctx` is NULL or a live context; `sect` is a C string.
unsafe fn gnames_from_sectname(ctx: *mut X509V3_CTX, sect: *const c_char) -> *mut GENERAL_NAMES {
    // SAFETY: the caller's guarantee.
    let at = unsafe { text(sect) }.and_then(|t| t.first().copied()) == Some(b'@');
    let gnsect = if at {
        // SAFETY: as above; the section's name after `@`.
        unsafe { X509V3_get_section(ctx, sect.wrapping_add(1)) }
    } else {
        // SAFETY: as above.
        unsafe { X509V3_parse_list(sect) }
    };
    if gnsect.is_null() {
        err::raise(
            ERR_LIB_X509V3,
            X509V3_R_SECTION_NOT_FOUND,
            "gnames_from_sectname",
        );
        return ptr::null_mut();
    }
    // SAFETY: the values.
    let gens = unsafe { v2i_GENERAL_NAMES(ptr::null(), ctx, gnsect) };
    if at {
        // SAFETY: the context's section.
        unsafe { X509V3_section_free(ctx, gnsect) };
    } else {
        // SAFETY: the list made above.
        unsafe { OPENSSL_sk_pop_free(gnsect.cast(), Some(free_conf)) };
    }
    gens
}

/// `X509_NAME_ENTRY_free` as a stack's free function.
unsafe extern "C" fn free_entry(e: *mut c_void) {
    // SAFETY: an entry of the stack, which the stack owned.
    unsafe { crate::x509::name::X509_NAME_ENTRY_free(e.cast()) };
}

/// `set_dist_point_name`: `fullname` (names, or `@section`) or `relativename` (a section of
/// one RDN) into `*pdp`: 1, 0 for another name, or -1 on failure.
///
/// # Safety
/// `pdp` holds NULL or a live name; `ctx` is NULL or a live context; `cnf` is live.
unsafe fn set_dist_point_name(
    pdp: &mut *mut DIST_POINT_NAME,
    ctx: *mut X509V3_CTX,
    cnf: &CONF_VALUE,
) -> c_int {
    const F: &str = "set_dist_point_name";
    // SAFETY: the value's name.
    let name = unsafe { text(cnf.name) }.unwrap_or_default();
    let full = name.starts_with(b"fullname");
    if !full && name != b"relativename" {
        return 0;
    }
    if cnf.value.is_null() {
        err::raise(ERR_LIB_X509V3, X509V3_R_MISSING_VALUE, F);
        return -1;
    }
    let mut fnm: *mut GENERAL_NAMES = ptr::null_mut();
    let mut rnm: *mut c_void = ptr::null_mut();
    let fail = |fnm: *mut GENERAL_NAMES, rnm: *mut c_void| {
        // SAFETY: made here, or NULL.
        unsafe { OPENSSL_sk_pop_free(fnm.cast(), Some(free_gen)) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_pop_free(rnm.cast(), Some(free_entry)) };
        -1
    };
    if full {
        // SAFETY: the caller's context; the value.
        fnm = unsafe { gnames_from_sectname(ctx, cnf.value) };
        if fnm.is_null() {
            return -1;
        }
    } else {
        // SAFETY: no preconditions.
        let nm = unsafe { X509_NAME_new() };
        if nm.is_null() {
            return -1;
        }
        // SAFETY: the caller's context; the value.
        let dnsect = unsafe { X509V3_get_section(ctx, cnf.value) };
        if dnsect.is_null() {
            // SAFETY: made above.
            unsafe { X509_NAME_free(nm) };
            err::raise(ERR_LIB_X509V3, X509V3_R_SECTION_NOT_FOUND, F);
            return -1;
        }
        // SAFETY: the new name; the section.
        let ret =
            unsafe { X509V3_NAME_from_section(nm, dnsect, MBSTRING_ASC.cast_unsigned().into()) };
        // SAFETY: the context's section.
        unsafe { X509V3_section_free(ctx, dnsect) };
        // SAFETY: the new name: its entries taken out.
        if let Some(n) = unsafe { name_of(nm) } {
            rnm = n.entries.cast();
            n.entries = ptr::null_mut();
        }
        // SAFETY: made above.
        unsafe { X509_NAME_free(nm) };
        // SAFETY: the entries, or NULL.
        let count = unsafe { OPENSSL_sk_num(rnm.cast()) };
        if ret == 0 || count <= 0 {
            return fail(fnm, rnm);
        }
        // SAFETY: the entries' last index.
        let lastp = unsafe { OPENSSL_sk_value(rnm.cast(), count.saturating_sub(1)) };
        // SAFETY: the last entry.
        let last = unsafe { entry_of(lastp.cast()) };
        if last.is_some_and(|e| e.set != 0) {
            err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_MULTIPLE_RDNS, F);
            return fail(fnm, rnm);
        }
    }
    if !pdp.is_null() {
        err::raise(ERR_LIB_X509V3, X509V3_R_DISTPOINT_ALREADY_SET, F);
        return fail(fnm, rnm);
    }
    // SAFETY: no preconditions.
    let dp = unsafe { DIST_POINT_NAME_new() };
    // SAFETY: new, or NULL.
    let Some(d) = (unsafe { dp.as_mut() }) else {
        return fail(fnm, rnm);
    };
    if fnm.is_null() {
        d.type_ = 1;
        d.name.relativename = rnm.cast();
    } else {
        d.type_ = 0;
        d.name.fullname = fnm;
    }
    *pdp = dp;
    1
}

static REASON_FLAGS: BitNames<10> = BitNames([
    reason(0, c"Unused", c"unused"),
    reason(1, c"Key Compromise", c"keyCompromise"),
    reason(2, c"CA Compromise", c"CACompromise"),
    reason(3, c"Affiliation Changed", c"affiliationChanged"),
    reason(4, c"Superseded", c"superseded"),
    reason(5, c"Cessation Of Operation", c"cessationOfOperation"),
    reason(6, c"Certificate Hold", c"certificateHold"),
    reason(7, c"Privilege Withdrawn", c"privilegeWithdrawn"),
    reason(8, c"AA Compromise", c"AACompromise"),
    BIT_STRING_BITNAME {
        bitnum: -1,
        lname: ptr::null(),
        sname: ptr::null(),
    },
]);

const fn reason(bitnum: c_int, lname: &'static CStr, sname: &'static CStr) -> BIT_STRING_BITNAME {
    BIT_STRING_BITNAME {
        bitnum,
        lname: lname.as_ptr(),
        sname: sname.as_ptr(),
    }
}

/// The reasons, with their names.
fn reasons() -> impl Iterator<Item = (c_int, &'static CStr, &'static CStr)> {
    REASON_FLAGS
        .0
        .iter()
        .filter(|r| !r.lname.is_null())
        .map(|r| {
            // SAFETY: static names.
            (r.bitnum, unsafe { CStr::from_ptr(r.lname) }, unsafe {
                CStr::from_ptr(r.sname)
            })
        })
}

/// `set_reasons`: a new BIT STRING of the reasons named (by their short names) in `value`
/// into `*preas`, which must be empty: true, or false.
///
/// # Safety
/// `value` is NULL or a C string.
unsafe fn set_reasons(preas: &mut *mut ASN1_BIT_STRING, value: *const c_char) -> bool {
    // SAFETY: the caller's guarantee.
    let rsk = unsafe { X509V3_parse_list(value) };
    if rsk.is_null() {
        return false;
    }
    let ok = 'set: {
        if !preas.is_null() {
            break 'set false;
        }
        // SAFETY: the list.
        let n = unsafe { OPENSSL_sk_num(rsk.cast()) };
        for i in 0..n {
            // SAFETY: an index within the list; a `CONF_VALUE`.
            let Some(v) = (unsafe { super::item_at::<CONF_VALUE>(rsk.cast(), i) }) else {
                continue;
            };
            if preas.is_null() {
                // SAFETY: no preconditions.
                *preas = unsafe { ASN1_BIT_STRING_new() };
                if preas.is_null() {
                    break 'set false;
                }
            }
            // SAFETY: its name.
            let bnam = unsafe { text(v.name) };
            let Some((bit, _, _)) = reasons().find(|r| Some(r.2.to_bytes()) == bnam) else {
                break 'set false;
            };
            // SAFETY: the BIT STRING made above.
            if unsafe { ASN1_BIT_STRING_set_bit(*preas, bit, 1) } == 0 {
                break 'set false;
            }
        }
        true
    };
    // SAFETY: the list made above.
    unsafe { OPENSSL_sk_pop_free(rsk.cast(), Some(free_conf)) };
    ok
}

/// `print_reasons`: `rname:` then the reasons set, by their long names, on the next line.
///
/// # Safety
/// `out` is a live BIO; `rflags` is a live BIT STRING.
unsafe fn print_reasons(out: *mut BIO, rname: &CStr, rflags: *mut ASN1_BIT_STRING, indent: c_int) {
    // SAFETY: the caller's BIO; a static format and its arguments.
    unsafe {
        BIO_printf(
            out,
            c"%*s%s:\n%*s".as_ptr(),
            indent,
            c"".as_ptr(),
            rname.as_ptr(),
            indent.saturating_add(2),
            c"".as_ptr(),
        )
    };
    let mut first = true;
    for (bit, lname, _) in reasons() {
        // SAFETY: the caller's BIT STRING.
        if unsafe { ASN1_BIT_STRING_get_bit(rflags, bit) } != 0 {
            if !first {
                // SAFETY: as above.
                unsafe { BIO_puts(out, c", ".as_ptr()) };
            }
            first = false;
            // SAFETY: as above.
            unsafe { BIO_puts(out, lname.as_ptr()) };
        }
    }
    let end = if first { c"<EMPTY>\n" } else { c"\n" };
    // SAFETY: as above.
    unsafe { BIO_puts(out, end.as_ptr()) };
}

/// `crldp_from_section`: a distribution point from a section's values.
///
/// # Safety
/// `ctx` is NULL or a live context; `nval` is a live stack of `CONF_VALUE`s.
unsafe fn crldp_from_section(
    ctx: *mut X509V3_CTX,
    nval: *mut stack_st_CONF_VALUE,
) -> *mut DIST_POINT {
    // SAFETY: no preconditions.
    let point = unsafe { DIST_POINT_new() };
    // SAFETY: new, or NULL.
    let Some(p) = (unsafe { point.as_mut() }) else {
        return ptr::null_mut();
    };
    let fail = || {
        // SAFETY: made above.
        unsafe { DIST_POINT_free(point) };
        ptr::null_mut()
    };
    // SAFETY: the caller's stack.
    let n = unsafe { OPENSSL_sk_num(nval.cast()) };
    for i in 0..n {
        // SAFETY: an index within the stack; a `CONF_VALUE`.
        let Some(cnf) = (unsafe { super::item_at::<CONF_VALUE>(nval.cast(), i) }) else {
            continue;
        };
        // SAFETY: the point's name; the caller's context; the value.
        match unsafe { set_dist_point_name(&mut p.distpoint, ctx, cnf) } {
            r if r > 0 => continue,
            r if r < 0 => return fail(),
            _ => {}
        }
        // SAFETY: its name.
        match unsafe { text(cnf.name) } {
            Some(b"reasons") => {
                // SAFETY: the point's reasons; the value.
                if !unsafe { set_reasons(&mut p.reasons, cnf.value) } {
                    return fail();
                }
            }
            Some(b"CRLissuer") => {
                // SAFETY: as above.
                p.CRLissuer = unsafe { gnames_from_sectname(ctx, cnf.value) };
                if p.CRLissuer.is_null() {
                    return fail();
                }
            }
            _ => {}
        }
    }
    point
}

/// `DIST_POINT_free` as a stack's free function.
unsafe extern "C" fn free_dp(p: *mut c_void) {
    // SAFETY: a point of the stack, which the stack owned.
    unsafe { DIST_POINT_free(p.cast()) };
}

/// A distribution point of one full name, or NULL.
///
/// # Safety
/// `gname` is a live name the point takes.
unsafe fn point_of_name(gname: *mut rustyssl_abi::GENERAL_NAME) -> *mut DIST_POINT {
    const F: &str = "v2i_crld";
    // SAFETY: no preconditions.
    let gens = unsafe { GENERAL_NAMES_new() };
    if gens.is_null() {
        err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
        // SAFETY: the caller's name.
        unsafe { GENERAL_NAME_free(gname) };
        return ptr::null_mut();
    }
    // SAFETY: the stack; the name, which it takes.
    if unsafe { OPENSSL_sk_push(gens.cast(), gname.cast()) } == 0 {
        err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, F);
        // SAFETY: as above.
        unsafe { GENERAL_NAME_free(gname) };
        // SAFETY: made above.
        unsafe { GENERAL_NAMES_free(gens) };
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    let point = unsafe { DIST_POINT_new() };
    // SAFETY: as above.
    let dpn = if point.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: no preconditions.
        unsafe { DIST_POINT_NAME_new() }
    };
    // SAFETY: new, or NULL.
    let (Some(p), Some(d)) = (unsafe { point.as_mut() }, unsafe { dpn.as_mut() }) else {
        err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
        // SAFETY: made above, or NULL.
        unsafe { DIST_POINT_free(point) };
        // SAFETY: as above.
        unsafe { GENERAL_NAMES_free(gens) };
        return ptr::null_mut();
    };
    d.name.fullname = gens;
    d.type_ = 0;
    p.distpoint = dpn;
    point
}

ffi_callback! {
    /// `v2i_crld`: a distribution point for each name (`URI:…`), or each section named
    /// without a value.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `nval` is NULL or a live stack of `CONF_VALUE`s.
    pub(crate) unsafe extern "C" fn crld_v2i(method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, nval: *mut stack_st_CONF_VALUE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's stack, or NULL.
        let num = unsafe { OPENSSL_sk_num(nval.cast()) };
        // SAFETY: no preconditions.
        let crld = unsafe { OPENSSL_sk_new_reserve(None, num) };
        if crld.is_null() {
            err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, "v2i_crld");
            return ptr::null_mut();
        }
        let fail = || {
            // SAFETY: the stack made above, with its points.
            unsafe { OPENSSL_sk_pop_free(crld, Some(free_dp)) };
            ptr::null_mut()
        };
        for i in 0..num {
            // SAFETY: an index within the stack; a `CONF_VALUE`.
            let cnf = unsafe { OPENSSL_sk_value(nval.cast(), i) }.cast::<CONF_VALUE>();
            // SAFETY: as above.
            let Some(c) = (unsafe { cnf.as_ref() }) else { continue };
            let point = if c.value.is_null() {
                // SAFETY: the caller's context; the section's name.
                let dpsect = unsafe { X509V3_get_section(ctx, c.name) };
                if dpsect.is_null() {
                    return fail();
                }
                // SAFETY: as above; the section.
                let point = unsafe { crldp_from_section(ctx, dpsect) };
                // SAFETY: the context's section.
                unsafe { X509V3_section_free(ctx, dpsect) };
                point
            } else {
                // SAFETY: the caller's context; the value.
                let gname = unsafe { v2i_GENERAL_NAME(method, ctx, cnf) };
                if gname.is_null() {
                    return fail();
                }
                // SAFETY: the name, which the point takes.
                unsafe { point_of_name(gname) }
            };
            if point.is_null() {
                return fail();
            }
            // SAFETY: the stack, with room reserved; the point, which it takes.
            unsafe { OPENSSL_sk_push(crld, point.cast()) };
        }
        crld.cast()
    }
}

ffi_callback! {
    /// `v2i_idp`: the distribution point name, `onlyuser`, `onlyCA`, `onlyAA`, `indirectCRL`
    /// (booleans), and `onlysomereasons`; any other name fails with `X509V3_R_INVALID_NAME`.
    ///
    /// # Safety
    /// As for [`crld_v2i`].
    pub(crate) unsafe extern "C" fn idp_v2i(_method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, nval: *mut stack_st_CONF_VALUE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: no preconditions.
        let idp = unsafe { ISSUING_DIST_POINT_new() };
        // SAFETY: new, or NULL.
        let Some(p) = (unsafe { idp.as_mut() }) else {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, "v2i_idp");
            return ptr::null_mut();
        };
        let fail = || {
            // SAFETY: made above.
            unsafe { ISSUING_DIST_POINT_free(idp) };
            ptr::null_mut()
        };
        // SAFETY: the caller's stack, or NULL.
        let n = unsafe { OPENSSL_sk_num(nval.cast()) };
        for i in 0..n {
            // SAFETY: an index within the stack; a `CONF_VALUE`.
            let cnfp = unsafe { OPENSSL_sk_value(nval.cast(), i) }.cast::<CONF_VALUE>();
            // SAFETY: as above.
            let Some(cnf) = (unsafe { cnfp.as_ref() }) else { continue };
            // SAFETY: the point's name; the caller's context; the value.
            match unsafe { set_dist_point_name(&mut p.distpoint, ctx, cnf) } {
                r if r > 0 => continue,
                r if r < 0 => return fail(),
                _ => {}
            }
            // SAFETY: its name.
            let field = match unsafe { text(cnf.name) } {
                Some(b"onlyuser") => Some(&raw mut p.onlyuser),
                Some(b"onlyCA") => Some(&raw mut p.onlyCA),
                Some(b"onlyAA") => Some(&raw mut p.onlyattr),
                Some(b"indirectCRL") => Some(&raw mut p.indirectCRL),
                _ => None,
            };
            // SAFETY: its name.
            let name = unsafe { text(cnf.name) };
            if let Some(f) = field {
                // SAFETY: the value; the field.
                if unsafe { X509V3_get_value_bool(cnfp, f) } == 0 {
                    return fail();
                }
            } else if name == Some(b"onlysomereasons") {
                // SAFETY: the point's reasons; the value.
                if !unsafe { set_reasons(&mut p.onlysomereasons, cnf.value) } {
                    return fail();
                }
            } else {
                err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_NAME, "v2i_idp");
                // SAFETY: the value.
                unsafe { add_error_name_value(cnf) };
                return fail();
            }
        }
        idp.cast()
    }
}

// Printing.

ffi_export! {
    /// Prints each name (`GENERAL_NAME_print`) on a line of its own, `indent + 2` in: 1.
    ///
    /// # Safety
    /// `out` is a live BIO; `gens` is NULL or a live stack of names.
    pub unsafe extern "C" fn OSSL_GENERAL_NAMES_print(out: *mut BIO, gens: *mut GENERAL_NAMES, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's stack, or NULL.
        let n = unsafe { OPENSSL_sk_num(gens.cast()) };
        for i in 0..n {
            if i > 0 {
                // SAFETY: the caller's BIO.
                unsafe { BIO_puts(out, c"\n".as_ptr()) };
            }
            // SAFETY: as above.
            unsafe { indent_to(out, indent.saturating_add(2)) };
            // SAFETY: an index within the stack.
            let g = unsafe { OPENSSL_sk_value(gens.cast(), i) };
            // SAFETY: as above; a name of the stack.
            unsafe { GENERAL_NAME_print(out, g.cast()) };
        }
        1
    }
}

/// `print_distpoint`: `Full Name:` and its names, or `Relative Name:` and the RDN.
///
/// # Safety
/// `out` is a live BIO; `dpn` is a live distribution point name.
unsafe fn print_distpoint(out: *mut BIO, dpn: &DIST_POINT_NAME, indent: c_int) {
    if dpn.type_ == 0 {
        // SAFETY: the caller's BIO; a static format and its arguments.
        unsafe { BIO_printf(out, c"%*sFull Name:\n".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: a full name's field.
        let names = unsafe { dpn.name.fullname };
        // SAFETY: as above; its names.
        unsafe { OSSL_GENERAL_NAMES_print(out, names, indent) };
    } else {
        // SAFETY: as above.
        unsafe {
            BIO_printf(
                out,
                c"%*sRelative Name:\n%*s".as_ptr(),
                indent,
                c"".as_ptr(),
                indent.saturating_add(2),
                c"".as_ptr(),
            )
        };
        // A name of its entries alone, as OpenSSL's on-stack one.
        // SAFETY: its entries.
        let tmp = Name::of_entries(unsafe { dpn.name.relativename }.cast());
        // SAFETY: as above; the name, which lives through the call.
        unsafe {
            X509_NAME_print_ex(
                out,
                ptr::from_ref(&tmp).cast::<X509_NAME>(),
                0,
                core::ffi::c_ulong::from(XN_FLAG_ONELINE.cast_unsigned()),
            )
        };
    }
    // SAFETY: as above.
    unsafe { BIO_puts(out, c"\n".as_ptr()) };
}

ffi_callback! {
    /// `i2r_idp`: the name, the restrictions, and the reasons; `<EMPTY>` for none.
    ///
    /// # Safety
    /// `ext` is a live IssuingDistributionPoint; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn idp_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(idp) = (unsafe { ext.cast::<ISSUING_DIST_POINT>().as_ref() }) else { return 0 };
        let line = |text: &CStr| {
            // SAFETY: the caller's BIO; a static format and its arguments.
            unsafe { BIO_printf(out, c"%*s%s\n".as_ptr(), indent, c"".as_ptr(), text.as_ptr()) };
        };
        // SAFETY: its name, or NULL.
        if let Some(d) = unsafe { idp.distpoint.as_ref() } {
            // SAFETY: as above.
            unsafe { print_distpoint(out, d, indent) };
        }
        if idp.onlyuser > 0 {
            line(c"Only User Certificates");
        }
        if idp.onlyCA > 0 {
            line(c"Only CA Certificates");
        }
        if idp.indirectCRL > 0 {
            line(c"Indirect CRL");
        }
        if !idp.onlysomereasons.is_null() {
            // SAFETY: as above; its reasons.
            unsafe { print_reasons(out, c"Only Some Reasons", idp.onlysomereasons, indent) };
        }
        if idp.onlyattr > 0 {
            line(c"Only Attribute Certificates");
        }
        if idp.distpoint.is_null() && idp.onlyuser <= 0 && idp.onlyCA <= 0 && idp.indirectCRL <= 0 && idp.onlysomereasons.is_null() && idp.onlyattr <= 0 {
            line(c"<EMPTY>");
        }
        1
    }
}

ffi_callback! {
    /// `i2r_crldp`: each point's name, reasons, and CRL issuer, separated by a blank line.
    ///
    /// # Safety
    /// `ext` is a live stack of distribution points; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn crldp_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's stack.
        let n = unsafe { OPENSSL_sk_num(ext.cast()) };
        for i in 0..n {
            if i > 0 {
                // SAFETY: the caller's BIO.
                unsafe { BIO_puts(out, c"\n".as_ptr()) };
            }
            // SAFETY: an index within the stack; a point.
            let Some(p) = (unsafe { super::item_at::<DIST_POINT>(ext.cast(), i) }) else { continue };
            // SAFETY: its name, or NULL.
            if let Some(d) = unsafe { p.distpoint.as_ref() } {
                // SAFETY: as above.
                unsafe { print_distpoint(out, d, indent) };
            }
            if !p.reasons.is_null() {
                // SAFETY: as above; its reasons.
                unsafe { print_reasons(out, c"Reasons", p.reasons, indent) };
            }
            if !p.CRLissuer.is_null() {
                // SAFETY: as above; a static format and its arguments.
                unsafe { BIO_printf(out, c"%*sCRL Issuer:\n".as_ptr(), indent, c"".as_ptr()) };
                // SAFETY: as above; its issuer's names.
                unsafe { OSSL_GENERAL_NAMES_print(out, p.CRLissuer, indent) };
            }
        }
        1
    }
}

ffi_callback! {
    /// `i2r_crl_invdate`: the invalidity date.
    ///
    /// # Safety
    /// `ext` is a live GeneralizedTime; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn invdate_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's BIO.
        if unsafe { indent_to(out, indent) } <= 0 {
            return 0;
        }
        // SAFETY: as above; the caller's time.
        c_int::from(unsafe { ASN1_GENERALIZEDTIME_print(out, ext.cast()) } != 0)
    }
}

ffi_callback! {
    /// `i2r_object`: the hold instruction's object.
    ///
    /// # Safety
    /// `ext` is a live object; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn object_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's BIO.
        if unsafe { indent_to(out, indent) } <= 0 {
            return 0;
        }
        // SAFETY: as above; the caller's object.
        c_int::from(unsafe { i2a_ASN1_OBJECT(out, ext.cast()) } > 0)
    }
}

/// `ossl_dist_point_name_full`: the issuer's name with the relative name's RDN appended.
///
/// # Safety
/// `dpn` is a live relative name; `iname` is a live name.
unsafe fn full_name(dpn: &DIST_POINT_NAME, iname: *const X509_NAME) -> *mut X509_NAME {
    // SAFETY: the caller's guarantee.
    let dpname = unsafe { X509_NAME_dup(iname) };
    if dpname.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the relative name's entries.
    let frag = unsafe { dpn.name.relativename };
    // SAFETY: as above.
    let n = unsafe { OPENSSL_sk_num(frag.cast()) };
    for i in 0..n {
        // SAFETY: an index within the entries.
        let ne = unsafe { OPENSSL_sk_value(frag.cast(), i) };
        // SAFETY: the copy; an entry, copied in.
        if unsafe { X509_NAME_add_entry(dpname, ne.cast(), -1, if i == 0 { 1 } else { 0 }) } == 0 {
            // SAFETY: made above.
            unsafe { X509_NAME_free(dpname) };
            return ptr::null_mut();
        }
    }
    // SAFETY: as above.
    if unsafe { crate::x509::name::i2d_X509_NAME(dpname, ptr::null_mut()) } < 0 {
        // SAFETY: as above.
        unsafe { X509_NAME_free(dpname) };
        return ptr::null_mut();
    }
    dpname
}

ffi_export! {
    /// For a relative name, sets its full name (`dpname`) relative to `iname`: 1, or 0; other
    /// names (and NULL) are left alone, 1.
    ///
    /// # Safety
    /// `dpn` is NULL or a live distribution point name; `iname` is a live name.
    pub unsafe extern "C" fn DIST_POINT_set_dpname(dpn: *mut DIST_POINT_NAME, iname: *const X509_NAME) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { dpn.as_mut() }) else { return 1 };
        if d.type_ != 1 {
            return 1;
        }
        // SAFETY: its own, or NULL.
        unsafe { X509_NAME_free(d.dpname) };
        // SAFETY: the relative name; the caller's name.
        d.dpname = unsafe { full_name(d, iname) };
        c_int::from(!d.dpname.is_null())
    }
}

// The attribute authority's issuing distribution point.

static AADP_TT: Templates<6> = Templates([
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(OSSL_AA_DIST_POINT, distpoint),
        c"distpoint",
        DIST_POINT_NAME_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(OSSL_AA_DIST_POINT, reasons),
        c"reasons",
        ASN1_BIT_STRING_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        2,
        offset_of!(OSSL_AA_DIST_POINT, indirectCRL),
        c"indirectCRL",
        ASN1_FBOOLEAN_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        3,
        offset_of!(OSSL_AA_DIST_POINT, containsUserAttributeCerts),
        c"containsUserAttributeCerts",
        ASN1_TBOOLEAN_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        4,
        offset_of!(OSSL_AA_DIST_POINT, containsAACerts),
        c"containsAACerts",
        ASN1_TBOOLEAN_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        5,
        offset_of!(OSSL_AA_DIST_POINT, containsSOAPublicKeyCerts),
        c"containsSOAPublicKeyCerts",
        ASN1_TBOOLEAN_it,
    ),
]);

item_fns! {
    /// An attribute authority's issuing distribution point.
    pub unsafe extern "C" fn OSSL_AA_DIST_POINT_it = sequence::<OSSL_AA_DIST_POINT, 6>(&AADP_TT, None, c"OSSL_AA_DIST_POINT");
}

new_free! {
    pub unsafe extern "C" fn OSSL_AA_DIST_POINT_new, pub unsafe extern "C" fn OSSL_AA_DIST_POINT_free(OSSL_AA_DIST_POINT) = OSSL_AA_DIST_POINT_it;
}

i2d! {
    /// Encodes an `OSSL_AA_DIST_POINT`.
    pub unsafe extern "C" fn i2d_OSSL_AA_DIST_POINT(OSSL_AA_DIST_POINT) = OSSL_AA_DIST_POINT_it;
}

d2i! {
    /// Decodes an `OSSL_AA_DIST_POINT` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_AA_DIST_POINT(OSSL_AA_DIST_POINT) = OSSL_AA_DIST_POINT_it;
}

/// `aaidp_from_section`: an attribute authority's distribution point from a section's values;
/// names other than the point's name, `reasons`, `indirectCRL`, and the three `contains…`
/// booleans are ignored.
///
/// # Safety
/// `ctx` is NULL or a live context; `nval` is a live stack of `CONF_VALUE`s.
unsafe fn aaidp_from_section(
    ctx: *mut X509V3_CTX,
    nval: *mut stack_st_CONF_VALUE,
) -> *mut OSSL_AA_DIST_POINT {
    // SAFETY: no preconditions.
    let point = unsafe { OSSL_AA_DIST_POINT_new() };
    // SAFETY: new, or NULL.
    let Some(p) = (unsafe { point.as_mut() }) else {
        return ptr::null_mut();
    };
    let fail = || {
        // SAFETY: made above.
        unsafe { OSSL_AA_DIST_POINT_free(point) };
        ptr::null_mut()
    };
    // SAFETY: the caller's stack.
    let n = unsafe { OPENSSL_sk_num(nval.cast()) };
    for i in 0..n {
        // SAFETY: an index within the stack; a `CONF_VALUE`.
        let cnfp = unsafe { OPENSSL_sk_value(nval.cast(), i) }.cast::<CONF_VALUE>();
        // SAFETY: as above.
        let Some(cnf) = (unsafe { cnfp.as_ref() }) else {
            continue;
        };
        // SAFETY: the point's name; the caller's context; the value.
        match unsafe { set_dist_point_name(&mut p.distpoint, ctx, cnf) } {
            r if r > 0 => continue,
            r if r < 0 => return fail(),
            _ => {}
        }
        // SAFETY: its name.
        let name = unsafe { text(cnf.name) };
        let field = match name {
            Some(b"indirectCRL") => Some(&raw mut p.indirectCRL),
            Some(b"containsUserAttributeCerts") => Some(&raw mut p.containsUserAttributeCerts),
            Some(b"containsAACerts") => Some(&raw mut p.containsAACerts),
            Some(b"containsSOAPublicKeyCerts") => Some(&raw mut p.containsSOAPublicKeyCerts),
            _ => None,
        };
        if let Some(f) = field {
            // SAFETY: the value; the field.
            if unsafe { X509V3_get_value_bool(cnfp, f) } == 0 {
                return fail();
            }
        } else if name == Some(b"reasons") {
            // SAFETY: the point's reasons; the value.
            if !unsafe { set_reasons(&mut p.reasons, cnf.value) } {
                return fail();
            }
        }
    }
    point
}

ffi_callback! {
    /// `v2i_aaidp`: the point from the section named by the first value (one without a value),
    /// or of the first value as a name (`URI:…`); the others are ignored.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `nval` is NULL or a live stack of `CONF_VALUE`s.
    pub(crate) unsafe extern "C" fn aaidp_v2i(method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, nval: *mut stack_st_CONF_VALUE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        const F: &str = "v2i_aaidp";
        // SAFETY: the caller's stack, or NULL.
        let cnf = unsafe { OPENSSL_sk_value(nval.cast(), 0) }.cast::<CONF_VALUE>();
        // SAFETY: a `CONF_VALUE` of the stack, or NULL.
        let Some(c) = (unsafe { cnf.as_ref() }) else { return ptr::null_mut() };
        if c.value.is_null() {
            // SAFETY: the caller's context; the section's name.
            let dpsect = unsafe { X509V3_get_section(ctx, c.name) };
            if dpsect.is_null() {
                return ptr::null_mut();
            }
            // SAFETY: as above; the section.
            let point = unsafe { aaidp_from_section(ctx, dpsect) };
            // SAFETY: the context's section.
            unsafe { X509V3_section_free(ctx, dpsect) };
            return point.cast();
        }
        // SAFETY: the caller's context; the value.
        let gname = unsafe { v2i_GENERAL_NAME(method, ctx, cnf) };
        if gname.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let gens = unsafe { GENERAL_NAMES_new() };
        if gens.is_null() {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
            // SAFETY: made above.
            unsafe { GENERAL_NAME_free(gname) };
            return ptr::null_mut();
        }
        // SAFETY: the stack; the name, which it takes.
        if unsafe { OPENSSL_sk_push(gens.cast(), gname.cast()) } == 0 {
            err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, F);
            // SAFETY: as above.
            unsafe { GENERAL_NAME_free(gname) };
            // SAFETY: as above.
            unsafe { GENERAL_NAMES_free(gens) };
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let point = unsafe { OSSL_AA_DIST_POINT_new() };
        // SAFETY: as above.
        let dpn = if point.is_null() { ptr::null_mut() } else { unsafe { DIST_POINT_NAME_new() } };
        // SAFETY: new, or NULL.
        let (Some(p), Some(d)) = (unsafe { point.as_mut() }, unsafe { dpn.as_mut() }) else {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
            // SAFETY: made above, or NULL.
            unsafe { OSSL_AA_DIST_POINT_free(point) };
            // SAFETY: as above.
            unsafe { GENERAL_NAMES_free(gens) };
            return ptr::null_mut();
        };
        d.name.fullname = gens;
        d.type_ = 0;
        p.distpoint = dpn;
        point.cast()
    }
}

ffi_callback! {
    /// `i2r_aaidp`: the point's name, its reasons, and the booleans that are true.
    ///
    /// # Safety
    /// `ext` is a live `OSSL_AA_DIST_POINT`; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn aaidp_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { ext.cast::<OSSL_AA_DIST_POINT>().as_ref() }) else { return 0 };
        // SAFETY: its name, live when set.
        if let Some(dpn) = unsafe { p.distpoint.as_ref() } {
            // SAFETY: the caller's BIO; the name.
            unsafe { print_distpoint(out, dpn, indent) };
        }
        if !p.reasons.is_null() {
            // SAFETY: as above; its reasons.
            unsafe { print_reasons(out, c"Reasons", p.reasons, indent) };
        }
        let flags = [
            (p.indirectCRL, c"Indirect CRL: "),
            (p.containsUserAttributeCerts, c"Contains User Attribute Certificates: "),
            (p.containsAACerts, c"Contains Attribute Authority (AA) Certificates: "),
            (p.containsSOAPublicKeyCerts, c"Contains Source Of Authority (SOA) Public Key Certificates: "),
        ];
        for (b, label) in flags {
            if b == 0 {
                continue;
            }
            // SAFETY: as above; a static format and its arguments.
            if unsafe { BIO_printf(out, c"%*s%s".as_ptr(), indent, c"".as_ptr(), label.as_ptr()) } <= 0 {
                return 0;
            }
            // `print_boolean`: any value but 0 is TRUE.
            // SAFETY: as above.
            if unsafe { BIO_puts(out, c"TRUE\n".as_ptr()) } <= 0 {
                return 0;
            }
        }
        1
    }
}

pub(crate) static AA_ISSUING_DIST_POINT: Method = Method({
    let mut m = method(NID_id_aa_issuing_distribution_point, 0);
    m.it = Some(OSSL_AA_DIST_POINT_it);
    m.v2i = Some(aaidp_v2i);
    m.i2r = Some(aaidp_i2r);
    m
});

const fn crld(nid: c_int) -> Method {
    let mut m = method(nid, 0);
    m.it = Some(CRL_DIST_POINTS_it);
    m.v2i = Some(crld_v2i);
    m.i2r = Some(crldp_i2r);
    Method(m)
}

pub(crate) static CRLD: Method = crld(NID_crl_distribution_points);
pub(crate) static FRESHEST_CRL: Method = crld(NID_freshest_crl);

pub(crate) static IDP: Method = Method({
    let mut m = method(NID_issuing_distribution_point, X509V3_EXT_MULTILINE);
    m.it = Some(ISSUING_DIST_POINT_it);
    m.v2i = Some(idp_v2i);
    m.i2r = Some(idp_i2r);
    m
});

pub(crate) static CRL_INVDATE: Method = Method({
    let mut m = method(NID_invalidity_date, 0);
    m.it = Some(ASN1_GENERALIZEDTIME_it);
    m.i2r = Some(invdate_i2r);
    m
});

pub(crate) static CRL_HOLD: Method = Method({
    let mut m = method(NID_hold_instruction_code, 0);
    m.it = Some(ASN1_OBJECT_it);
    m.i2r = Some(object_i2r);
    m
});
