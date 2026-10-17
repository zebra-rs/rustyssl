//! The RFC 3779 extensions (`v3_addr.c`, `v3_asid.c`): IP address delegation (`IPAddrBlocks`, a
//! SEQUENCE of address families, each inheriting or listing prefixes and ranges) and AS
//! identifier delegation (`ASIdentifiers`, AS numbers and routing domain identifiers, each
//! inheriting or listing numbers and ranges).
//!
//! As OpenSSL's:
//! - Both are made from text (`IPv4:10.0.0.0/8`, `IPv6-SAFI:1:2001:db8::-2001:db8::ff`,
//!   `AS:64496-64511`, `RDI:inherit`), then put in canonical form: sorted, with adjacent
//!   entries merged and ranges that are prefixes written as prefixes. Overlaps are refused.
//! - Sorting goes through the stack's comparison: a list decoded from DER has none, so
//!   `X509v3_addr_canonize` and `X509v3_asid_canonize` leave it in its order (and then fail if
//!   that isn't canonical), as OpenSSL's do.
//! - `X509v3_addr_get_afi` reads two octets only when there are two (CVE-2017-3735), and an
//!   address longer than its family's length is refused rather than copied.
//! - The path checks (`X509v3_addr_validate_path`, `X509v3_asid_validate_path`, and the
//!   `_validate_resource_set` functions) read the certificates' cached extensions, and come
//!   with path validation (step 5.4).

use core::cmp::Ordering;
use core::ffi::{CStr, c_char, c_int, c_uchar, c_uint, c_void};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASIdOrRange, ASIdOrRange_id, ASIdOrRange_range, ASIdOrRanges, ASIdentifierChoice,
    ASIdentifierChoice_asIdsOrRanges, ASIdentifierChoice_inherit, ASIdentifiers, ASN1_BIT_STRING,
    ASN1_INTEGER, ASN1_ITEM, ASN1_ITYPE_PRIMITIVE, ASN1_OCTET_STRING, ASN1_STRING_FLAG_BITS_LEFT,
    ASN1_TFLG_EXPLICIT, ASN1_TFLG_OPTIONAL, ASN1_TFLG_SEQUENCE_OF, ASRange, BIO, CONF_VALUE,
    ERR_LIB_ASN1, ERR_LIB_X509V3, ERR_R_ASN1_LIB, ERR_R_BN_LIB, ERR_R_CRYPTO_LIB, ERR_R_X509V3_LIB,
    IANA_AFI_IPV4, IANA_AFI_IPV6, IPAddrBlocks, IPAddressChoice, IPAddressChoice_addressesOrRanges,
    IPAddressChoice_inherit, IPAddressFamily, IPAddressOrRange, IPAddressOrRange_addressPrefix,
    IPAddressOrRange_addressRange, IPAddressOrRanges, IPAddressRange, NID_sbgp_autonomousSysNum,
    NID_sbgp_ipAddrBlock, V3_ASID_ASNUM, V3_ASID_RDI, X509, X509_STORE_CTX,
    X509_V_ERR_INVALID_EXTENSION, X509_V_ERR_OUT_OF_MEM, X509_V_ERR_UNNESTED_RESOURCE,
    X509_V_ERR_UNSPECIFIED, X509V3_CTX, X509V3_EXT_METHOD, X509V3_R_EXTENSION_NAME_ERROR,
    X509V3_R_EXTENSION_VALUE_ERROR, X509V3_R_INVALID_ASNUMBER, X509V3_R_INVALID_ASRANGE,
    X509V3_R_INVALID_INHERITANCE, X509V3_R_INVALID_IPADDRESS, X509V3_R_INVALID_NULL_ARGUMENT,
    X509V3_R_INVALID_SAFI, X509V3_R_MISSING_VALUE, stack_st_CONF_VALUE, stack_st_X509,
};

use super::registry::{Method, indent_to, method};
use super::san::name_is;
use super::simple::{X509V3_get_value_int, add_error_name_value};
use super::{i2s_ASN1_INTEGER, item_at, s2i_ASN1_INTEGER};
use crate::asn1::bit_string::ASN1_BIT_STRING_set;
use crate::asn1::integer::ASN1_INTEGER_cmp;
use crate::asn1::string::{
    ASN1_BIT_STRING_new, ASN1_INTEGER_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set,
};
use crate::asn1::tpl::items::{
    ASN1_BIT_STRING_it, ASN1_INTEGER_it, ASN1_NULL_it, ASN1_NULL_new, ASN1_OCTET_STRING_it, d2i,
    i2d, new_free,
};
use crate::asn1::tpl::statics::{Templates, choice, sequence};
use crate::asn1::tpl::{Template, item, item_fns, template, template_at};
use crate::bio::BIO_write;
use crate::bn::arith::BN_add_word;
use crate::bn::conv::{ASN1_INTEGER_to_BN, BN_to_ASN1_INTEGER};
use crate::bn::{BN_free, BN_new};
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_dup, OPENSSL_sk_find, OPENSSL_sk_free, OPENSSL_sk_new,
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_reserve,
    OPENSSL_sk_set, OPENSSL_sk_set_cmp_func, OPENSSL_sk_sort, OPENSSL_sk_value,
};
use crate::x509::ctx::ctx_of;
use crate::x509::purpose::cache_view;

/// `ADDR_RAW_BUF_LEN`: room for the longest address, IPv6's.
const RAW: usize = 16;

/// Writes `s` to the BIO.
///
/// # Safety
/// `out` is a live BIO.
unsafe fn puts(out: *mut BIO, s: &[u8]) {
    let n = c_int::try_from(s.len()).unwrap_or(c_int::MAX);
    // SAFETY: the caller's BIO; the octets.
    unsafe { BIO_write(out, s.as_ptr().cast(), n) };
}

/// The `n` octets at `p`: none for 0, `None` for NULL.
///
/// # Safety
/// `p` is NULL or holds `n` octets.
unsafe fn octets<'a>(p: *const c_uchar, n: usize) -> Option<&'a [u8]> {
    if n == 0 {
        return Some(&[]);
    }
    // SAFETY: the caller's guarantee.
    (!p.is_null()).then(|| unsafe { core::slice::from_raw_parts(p, n) })
}

/// A string's octets, or `None` for a negative length or no data.
///
/// # Safety
/// `s` is a live string.
unsafe fn string_octets<'a>(s: &ASN1_OCTET_STRING) -> Option<&'a [u8]> {
    let n = usize::try_from(s.length).ok()?;
    // SAFETY: a string's data holds its length.
    unsafe { octets(s.data, n) }
}

/// A NUL-terminated copy of `t`, for the C string functions.
fn c_text(t: &[u8]) -> Vec<u8> {
    let mut v = t.to_vec();
    v.push(0);
    v
}

/// A C string's bytes, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a C string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) }.to_bytes())
}

/// `strspn`: how many of `t`'s first bytes are in `set`.
fn span(t: &[u8], set: &[u8]) -> usize {
    t.iter().take_while(|c| set.contains(c)).count()
}

/// `strtoul(s, &end, base)` for base 0 (C's prefixes) or 10: the value (saturated, and negated
/// for `-`, as C's) and how many bytes it read (0 for no number).
fn strtoul(s: &[u8], base0: bool) -> (u64, usize) {
    let mut i = s
        .iter()
        .take_while(|c| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
        .count();
    let neg = match s.get(i) {
        Some(b'-') => {
            i = i.saturating_add(1);
            true
        }
        Some(b'+') => {
            i = i.saturating_add(1);
            false
        }
        _ => false,
    };
    let at = |k: usize| s.get(k).copied();
    let mut radix = 10u32;
    if base0 && at(i) == Some(b'0') {
        let hex_digit = at(i.saturating_add(2)).is_some_and(|c| c.is_ascii_hexdigit());
        if matches!(at(i.saturating_add(1)), Some(b'x' | b'X')) && hex_digit {
            radix = 16;
            i = i.saturating_add(2);
        } else {
            radix = 8;
        }
    }
    let start = i;
    let mut v: u64 = 0;
    let mut over = false;
    while let Some(d) = at(i).and_then(|c| char::from(c).to_digit(radix)) {
        match v
            .checked_mul(u64::from(radix))
            .and_then(|x| x.checked_add(u64::from(d)))
        {
            Some(x) => v = x,
            None => over = true,
        }
        i = i.saturating_add(1);
    }
    if i == start {
        return (0, 0);
    }
    if over {
        return (u64::MAX, i);
    }
    (if neg { v.wrapping_neg() } else { v }, i)
}

/// The low 32 bits of `v`, as C's conversion to `unsigned` keeps them.
fn low32(v: u64) -> u32 {
    u32::try_from(v & 0xffff_ffff).unwrap_or(0)
}

// The AS identifiers (`v3_asid.c`).

static ASRANGE_TT: Templates<2> = Templates([
    template_at(0, 0, offset_of!(ASRange, min), c"min", ASN1_INTEGER_it),
    template_at(0, 0, offset_of!(ASRange, max), c"max", ASN1_INTEGER_it),
]);

item_fns! {
    /// ASRange: SEQUENCE { min INTEGER, max INTEGER }.
    pub unsafe extern "C" fn ASRange_it = sequence::<ASRange, 2>(&ASRANGE_TT, None, c"ASRange");
}

new_free! {
    pub unsafe extern "C" fn ASRange_new, pub unsafe extern "C" fn ASRange_free(ASRange) = ASRange_it;
}

i2d! {
    /// Encodes an ASRange.
    pub unsafe extern "C" fn i2d_ASRange(ASRange) = ASRange_it;
}

d2i! {
    /// Decodes an ASRange (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASRange(ASRange) = ASRange_it;
}

static ASIDORRANGE_TT: Templates<2> = Templates([
    template_at(0, 0, offset_of!(ASIdOrRange, u), c"u.id", ASN1_INTEGER_it),
    template_at(0, 0, offset_of!(ASIdOrRange, u), c"u.range", ASRange_it),
]);

item_fns! {
    /// ASIdOrRange: CHOICE { id INTEGER, range ASRange }.
    pub unsafe extern "C" fn ASIdOrRange_it = choice::<ASIdOrRange, 2>(&ASIDORRANGE_TT, offset_of!(ASIdOrRange, type_), None, c"ASIdOrRange");
}

new_free! {
    pub unsafe extern "C" fn ASIdOrRange_new, pub unsafe extern "C" fn ASIdOrRange_free(ASIdOrRange) = ASIdOrRange_it;
}

i2d! {
    /// Encodes an ASIdOrRange.
    pub unsafe extern "C" fn i2d_ASIdOrRange(ASIdOrRange) = ASIdOrRange_it;
}

d2i! {
    /// Decodes an ASIdOrRange (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASIdOrRange(ASIdOrRange) = ASIdOrRange_it;
}

static ASIDCHOICE_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(ASIdentifierChoice, u),
        c"u.inherit",
        ASN1_NULL_it,
    ),
    template_at(
        ASN1_TFLG_SEQUENCE_OF,
        0,
        offset_of!(ASIdentifierChoice, u),
        c"u.asIdsOrRanges",
        ASIdOrRange_it,
    ),
]);

item_fns! {
    /// ASIdentifierChoice: CHOICE { inherit NULL, asIdsOrRanges SEQUENCE OF ASIdOrRange }.
    pub unsafe extern "C" fn ASIdentifierChoice_it = choice::<ASIdentifierChoice, 2>(&ASIDCHOICE_TT, offset_of!(ASIdentifierChoice, type_), None, c"ASIdentifierChoice");
}

new_free! {
    pub unsafe extern "C" fn ASIdentifierChoice_new, pub unsafe extern "C" fn ASIdentifierChoice_free(ASIdentifierChoice) = ASIdentifierChoice_it;
}

i2d! {
    /// Encodes an ASIdentifierChoice.
    pub unsafe extern "C" fn i2d_ASIdentifierChoice(ASIdentifierChoice) = ASIdentifierChoice_it;
}

d2i! {
    /// Decodes an ASIdentifierChoice (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASIdentifierChoice(ASIdentifierChoice) = ASIdentifierChoice_it;
}

static ASIDS_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(ASIdentifiers, asnum),
        c"asnum",
        ASIdentifierChoice_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(ASIdentifiers, rdi),
        c"rdi",
        ASIdentifierChoice_it,
    ),
]);

item_fns! {
    /// ASIdentifiers: SEQUENCE { asnum [0] EXPLICIT ASIdentifierChoice OPTIONAL, rdi [1]
    /// EXPLICIT ASIdentifierChoice OPTIONAL }.
    pub unsafe extern "C" fn ASIdentifiers_it = sequence::<ASIdentifiers, 2>(&ASIDS_TT, None, c"ASIdentifiers");
}

new_free! {
    pub unsafe extern "C" fn ASIdentifiers_new, pub unsafe extern "C" fn ASIdentifiers_free(ASIdentifiers) = ASIdentifiers_it;
}

i2d! {
    /// Encodes ASIdentifiers.
    pub unsafe extern "C" fn i2d_ASIdentifiers(ASIdentifiers) = ASIdentifiers_it;
}

d2i! {
    /// Decodes ASIdentifiers (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASIdentifiers(ASIdentifiers) = ASIdentifiers_it;
}

/// An identifier's list, read from the choice whatever its type (as OpenSSL reads the union).
fn as_list(c: &ASIdentifierChoice) -> *mut ASIdOrRanges {
    // SAFETY: both members are pointers.
    unsafe { c.u.asIdsOrRanges }
}

/// `extract_min_max`: an identifier's (or range's) least and greatest numbers.
fn as_min_max(aor: Option<&ASIdOrRange>) -> Option<(*mut ASN1_INTEGER, *mut ASN1_INTEGER)> {
    let aor = aor?;
    match aor.type_ {
        t if t == ASIdOrRange_id => {
            // SAFETY: an identifier's member.
            let id = unsafe { aor.u.id };
            Some((id, id))
        }
        t if t == ASIdOrRange_range => {
            // SAFETY: a range's member.
            let r = unsafe { aor.u.range };
            // SAFETY: the range, or NULL.
            let r = unsafe { r.as_ref() }?;
            Some((r.min, r.max))
        }
        _ => None,
    }
}

/// `ASN1_INTEGER_cmp`.
fn icmp(a: *const ASN1_INTEGER, b: *const ASN1_INTEGER) -> c_int {
    // SAFETY: INTEGERs of the lists, or NULL.
    unsafe { ASN1_INTEGER_cmp(a, b) }
}

/// The element `i` of a list, or `None`.
///
/// # Safety
/// `sk` is NULL or a live stack of `T`s.
unsafe fn at<'a, T>(sk: *mut c_void, i: c_int) -> Option<&'a mut T> {
    // SAFETY: the caller's guarantee.
    unsafe { item_at::<T>(sk.cast(), i) }
}

/// `ASIdOrRange_cmp`: by least number, an identifier before a range starting with it.
unsafe extern "C" fn as_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: pointers to the stack's elements.
    let a = unsafe { *a.cast::<*const ASIdOrRange>() };
    // SAFETY: as above.
    let b = unsafe { *b.cast::<*const ASIdOrRange>() };
    // SAFETY: elements of the stack.
    let (Some(a), Some(b)) = (unsafe { a.as_ref() }, unsafe { b.as_ref() }) else {
        return 0;
    };
    let (Some((amin, amax)), Some((bmin, bmax))) = (as_min_max(Some(a)), as_min_max(Some(b)))
    else {
        return 0;
    };
    match (a.type_ == ASIdOrRange_id, b.type_ == ASIdOrRange_id) {
        (true, true) | (true, false) | (false, true) => icmp(amin, bmin),
        (false, false) => match icmp(amin, bmin) {
            0 => icmp(amax, bmax),
            r => r,
        },
    }
}

/// The choice `which` selects, or `None`.
fn as_choice(asid: &mut ASIdentifiers, which: c_int) -> Option<&mut *mut ASIdentifierChoice> {
    match which {
        V3_ASID_ASNUM => Some(&mut asid.asnum),
        V3_ASID_RDI => Some(&mut asid.rdi),
        _ => None,
    }
}

ffi_export! {
    /// Makes the AS numbers (`V3_ASID_ASNUM`) or routing domain identifiers (`V3_ASID_RDI`)
    /// inherit if they're absent: 1 if they then inherit, otherwise 0.
    ///
    /// # Safety
    /// `asid` is NULL or live ASIdentifiers.
    pub unsafe extern "C" fn X509v3_asid_add_inherit(asid: *mut ASIdentifiers, which: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(asid) = (unsafe { asid.as_mut() }) else { return 0 };
        let Some(choice) = as_choice(asid, which) else { return 0 };
        if choice.is_null() {
            // SAFETY: no preconditions.
            let c = unsafe { ASIdentifierChoice_new() };
            // SAFETY: new, or NULL.
            let Some(cr) = (unsafe { c.as_mut() }) else { return 0 };
            // SAFETY: no preconditions.
            let null = unsafe { ASN1_NULL_new() };
            if null.is_null() {
                // SAFETY: made above.
                unsafe { ASIdentifierChoice_free(c) };
                return 0;
            }
            cr.u.inherit = null;
            cr.type_ = ASIdentifierChoice_inherit;
            *choice = c;
        }
        // SAFETY: the choice, made or the caller's.
        c_int::from(unsafe { (**choice).type_ } == ASIdentifierChoice_inherit)
    }
}

ffi_export! {
    /// Adds the number `min` (`max` NULL) or the range from `min` to `max` to the AS numbers or
    /// routing domain identifiers, which take them on success: 1, or 0 (also if they inherit).
    ///
    /// # Safety
    /// `asid` is NULL or live ASIdentifiers; `min` and `max` are NULL or INTEGERs the caller
    /// gives up on success.
    pub unsafe extern "C" fn X509v3_asid_add_id_or_range(asid: *mut ASIdentifiers, which: c_int, min: *mut ASN1_INTEGER, max: *mut ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(asid) = (unsafe { asid.as_mut() }) else { return 0 };
        let Some(choice) = as_choice(asid, which) else { return 0 };
        // SAFETY: the choice, or NULL.
        if let Some(c) = unsafe { choice.as_ref() }
            && c.type_ != ASIdentifierChoice_asIdsOrRanges
        {
            return 0;
        }
        if choice.is_null() {
            // SAFETY: no preconditions.
            let c = unsafe { ASIdentifierChoice_new() };
            // SAFETY: new, or NULL.
            let Some(cr) = (unsafe { c.as_mut() }) else { return 0 };
            // SAFETY: a comparison of the list's elements.
            let list = unsafe { OPENSSL_sk_new(Some(as_cmp)) };
            if list.is_null() {
                // SAFETY: made above.
                unsafe { ASIdentifierChoice_free(c) };
                return 0;
            }
            cr.u.asIdsOrRanges = list.cast();
            cr.type_ = ASIdentifierChoice_asIdsOrRanges;
            *choice = c;
        }
        // SAFETY: the choice, made or the caller's.
        let list = as_list(unsafe { &**choice });
        // SAFETY: no preconditions.
        let aor = unsafe { ASIdOrRange_new() };
        // SAFETY: new, or NULL.
        let Some(a) = (unsafe { aor.as_mut() }) else { return 0 };
        let fail = || {
            // SAFETY: made above.
            unsafe { ASIdOrRange_free(aor) };
            0
        };
        // SAFETY: the list.
        if unsafe { OPENSSL_sk_reserve(list.cast(), 1) } == 0 {
            return fail();
        }
        if max.is_null() {
            a.type_ = ASIdOrRange_id;
            a.u.id = min;
        } else {
            a.type_ = ASIdOrRange_range;
            // SAFETY: no preconditions.
            let r = unsafe { ASRange_new() };
            a.u.range = r;
            // SAFETY: new, or NULL.
            let Some(rr) = (unsafe { r.as_mut() }) else { return fail() };
            // SAFETY: its own.
            unsafe { ASN1_INTEGER_free(rr.min) };
            rr.min = min;
            // SAFETY: as above.
            unsafe { ASN1_INTEGER_free(rr.max) };
            rr.max = max;
        }
        // SAFETY: the list, with room; the element, which it takes.
        if unsafe { OPENSSL_sk_push(list.cast(), aor.cast()) } == 0 {
            return fail();
        }
        1
    }
}

/// `a_max + 1` in `slot` (replacing what's there), or `false` with an error.
fn plus_one(
    a_max: *const ASN1_INTEGER,
    bn: &mut *mut rustyssl_abi::BIGNUM,
    slot: &mut *mut ASN1_INTEGER,
    f: &str,
) -> bool {
    if bn.is_null() {
        // SAFETY: no preconditions.
        *bn = unsafe { BN_new() };
    }
    // SAFETY: the INTEGER, or NULL; the number, or NULL.
    let ok = !bn.is_null() && !unsafe { ASN1_INTEGER_to_BN(a_max, *bn) }.is_null() && {
        // SAFETY: the number.
        (unsafe { BN_add_word(*bn, 1) } != 0)
    };
    if !ok {
        err::raise(ERR_LIB_X509V3, ERR_R_BN_LIB, f);
        return false;
    }
    // SAFETY: the number; the INTEGER to reuse, or NULL.
    let r = unsafe { BN_to_ASN1_INTEGER(*bn, *slot) };
    if r.is_null() {
        err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, f);
        return false;
    }
    *slot = r;
    true
}

/// Frees what [`plus_one`] made.
fn free_scratch(bn: *mut rustyssl_abi::BIGNUM, one: *mut ASN1_INTEGER) {
    // SAFETY: made by `plus_one`, or NULL.
    unsafe { ASN1_INTEGER_free(one) };
    // SAFETY: as above.
    unsafe { BN_free(bn) };
}

/// `ASIdentifierChoice_is_canonical`.
fn as_choice_canonical(choice: *mut ASIdentifierChoice) -> bool {
    // SAFETY: the caller's choice, or NULL.
    let Some(c) = (unsafe { choice.as_ref() }) else {
        return true;
    };
    if c.type_ == ASIdentifierChoice_inherit {
        return true;
    }
    let list = as_list(c);
    // SAFETY: the list, or NULL.
    let n = unsafe { OPENSSL_sk_num(list.cast()) };
    if c.type_ != ASIdentifierChoice_asIdsOrRanges || n == 0 {
        return false;
    }
    let mut bn = ptr::null_mut();
    let mut one = ptr::null_mut();
    let ok = (|| {
        for i in 0..n.saturating_sub(1) {
            // SAFETY: indices within the list.
            let a = unsafe { at::<ASIdOrRange>(list.cast(), i) };
            // SAFETY: as above.
            let b = unsafe { at::<ASIdOrRange>(list.cast(), i.wrapping_add(1)) };
            let (Some((amin, amax)), Some((bmin, bmax))) =
                (as_min_max(a.map(|x| &*x)), as_min_max(b.map(|x| &*x)))
            else {
                return false;
            };
            if icmp(amin, bmin) >= 0 || icmp(amin, amax) > 0 || icmp(bmin, bmax) > 0 {
                return false;
            }
            if !plus_one(amax, &mut bn, &mut one, "ASIdentifierChoice_is_canonical") {
                return false;
            }
            if icmp(one, bmin) >= 0 {
                return false;
            }
        }
        // SAFETY: an index within the list, or none.
        let last = unsafe { at::<ASIdOrRange>(list.cast(), n.wrapping_sub(1)) };
        if let Some(a) = last
            && a.type_ == ASIdOrRange_range
        {
            match as_min_max(Some(a)) {
                Some((amin, amax)) if icmp(amin, amax) <= 0 => {}
                _ => return false,
            }
        }
        true
    })();
    free_scratch(bn, one);
    ok
}

ffi_export! {
    /// Whether the AS numbers and routing domain identifiers are in canonical form: 1 (also for
    /// NULL), or 0.
    ///
    /// # Safety
    /// `asid` is NULL or live ASIdentifiers.
    pub unsafe extern "C" fn X509v3_asid_is_canonical(asid: *mut ASIdentifiers) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { asid.as_ref() }) else { return 1 };
        c_int::from(as_choice_canonical(a.asnum) && as_choice_canonical(a.rdi))
    }
}

/// `ASIdentifierChoice_canonize`.
fn as_choice_canonize(choice: *mut ASIdentifierChoice) -> bool {
    const F: &str = "ASIdentifierChoice_canonize";
    // SAFETY: the caller's choice, or NULL.
    let Some(c) = (unsafe { choice.as_ref() }) else {
        return true;
    };
    if c.type_ == ASIdentifierChoice_inherit {
        return true;
    }
    let list = as_list(c);
    // SAFETY: the list, or NULL.
    if c.type_ != ASIdentifierChoice_asIdsOrRanges || unsafe { OPENSSL_sk_num(list.cast()) } == 0 {
        err::raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR, F);
        return false;
    }
    // SAFETY: the list (sorted only if it has a comparison).
    unsafe { OPENSSL_sk_sort(list.cast()) };
    let mut bn = ptr::null_mut();
    let mut one = ptr::null_mut();
    let ok = (|| {
        let mut i: c_int = 0;
        // SAFETY: the list.
        while i < unsafe { OPENSSL_sk_num(list.cast()) }.saturating_sub(1) {
            // SAFETY: indices within the list.
            let a = unsafe { at::<ASIdOrRange>(list.cast(), i) };
            // SAFETY: as above.
            let bp =
                unsafe { OPENSSL_sk_value(list.cast(), i.wrapping_add(1)) }.cast::<ASIdOrRange>();
            // SAFETY: an element of the list, or NULL.
            let b = unsafe { bp.as_mut() };
            let (Some(a), Some(b)) = (a, b) else {
                return false;
            };
            let (Some((amin, amax)), Some((bmin, bmax))) =
                (as_min_max(Some(a)), as_min_max(Some(b)))
            else {
                return false;
            };
            if icmp(amin, bmin) > 0 {
                return false;
            }
            if icmp(amin, amax) > 0 || icmp(bmin, bmax) > 0 {
                return false;
            }
            if icmp(amax, bmin) >= 0 {
                err::raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR, F);
                return false;
            }
            if !plus_one(amax, &mut bn, &mut one, F) {
                return false;
            }
            if icmp(one, bmin) == 0 {
                // Merge b into a: a keeps its least number and takes b's greatest.
                match a.type_ {
                    t if t == ASIdOrRange_id => {
                        // SAFETY: no preconditions.
                        let r = unsafe { ASRange_new() };
                        // SAFETY: new, or NULL.
                        let Some(rr) = (unsafe { r.as_mut() }) else {
                            return false;
                        };
                        // SAFETY: its own.
                        unsafe { ASN1_INTEGER_free(rr.min) };
                        // SAFETY: as above.
                        unsafe { ASN1_INTEGER_free(rr.max) };
                        rr.min = amin;
                        rr.max = bmax;
                        a.type_ = ASIdOrRange_range;
                        a.u.range = r;
                    }
                    _ => {
                        // SAFETY: a range's member.
                        let r = unsafe { a.u.range };
                        // SAFETY: the range, which `as_min_max` found.
                        let Some(rr) = (unsafe { r.as_mut() }) else {
                            return false;
                        };
                        // SAFETY: its own.
                        unsafe { ASN1_INTEGER_free(rr.max) };
                        rr.max = bmax;
                    }
                }
                if b.type_ == ASIdOrRange_id {
                    b.u.id = ptr::null_mut();
                } else {
                    // SAFETY: a range's member.
                    let r = unsafe { b.u.range };
                    // SAFETY: the range, which `as_min_max` found.
                    if let Some(rr) = unsafe { r.as_mut() } {
                        rr.max = ptr::null_mut();
                    }
                }
                // SAFETY: the element, whose greatest number a took.
                unsafe { ASIdOrRange_free(bp) };
                // SAFETY: the list; an index within it.
                unsafe { OPENSSL_sk_delete(list.cast(), i.wrapping_add(1)) };
                continue;
            }
            i = i.wrapping_add(1);
        }
        // SAFETY: the list.
        let n = unsafe { OPENSSL_sk_num(list.cast()) };
        // SAFETY: an index within the list, or none.
        let last = unsafe { at::<ASIdOrRange>(list.cast(), n.wrapping_sub(1)) };
        if let Some(a) = last
            && a.type_ == ASIdOrRange_range
        {
            match as_min_max(Some(a)) {
                Some((amin, amax)) if icmp(amin, amax) <= 0 => {}
                _ => return false,
            }
        }
        as_choice_canonical(choice)
    })();
    free_scratch(bn, one);
    ok
}

ffi_export! {
    /// Puts the AS numbers and routing domain identifiers in canonical form: sorted (if their
    /// lists have a comparison), adjacent entries merged; 1 (also for NULL), or 0 for an empty
    /// list or an overlap.
    ///
    /// # Safety
    /// `asid` is NULL or live ASIdentifiers.
    pub unsafe extern "C" fn X509v3_asid_canonize(asid: *mut ASIdentifiers) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { asid.as_ref() }) else { return 1 };
        c_int::from(as_choice_canonize(a.asnum) && as_choice_canonize(a.rdi))
    }
}

ffi_export! {
    /// Whether the AS numbers or routing domain identifiers inherit: 1, or 0.
    ///
    /// # Safety
    /// `asid` is NULL or live ASIdentifiers.
    pub unsafe extern "C" fn X509v3_asid_inherits(asid: *mut ASIdentifiers) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { asid.as_ref() }) else { return 0 };
        let inherits = |c: *mut ASIdentifierChoice| {
            // SAFETY: a choice of the identifiers, or NULL.
            unsafe { c.as_ref() }.is_some_and(|c| c.type_ == ASIdentifierChoice_inherit)
        };
        c_int::from(inherits(a.asnum) || inherits(a.rdi))
    }
}

/// `asid_contains`: whether every entry of `child` is within one of `parent`'s.
fn as_contains(parent: *mut ASIdOrRanges, child: *mut ASIdOrRanges) -> bool {
    if child.is_null() || parent == child {
        return true;
    }
    if parent.is_null() {
        return false;
    }
    let mut p: c_int = 0;
    // SAFETY: the lists.
    let (nc, np) = (unsafe { OPENSSL_sk_num(child.cast()) }, unsafe {
        OPENSSL_sk_num(parent.cast())
    });
    for c in 0..nc {
        // SAFETY: an index within the child.
        let Some((cmin, cmax)) =
            as_min_max(unsafe { at::<ASIdOrRange>(child.cast(), c) }.map(|x| &*x))
        else {
            return false;
        };
        loop {
            if p >= np {
                return false;
            }
            // SAFETY: an index within the parent.
            let Some((pmin, pmax)) =
                as_min_max(unsafe { at::<ASIdOrRange>(parent.cast(), p) }.map(|x| &*x))
            else {
                return false;
            };
            if icmp(pmax, cmax) < 0 {
                p = p.wrapping_add(1);
                continue;
            }
            if icmp(pmin, cmin) > 0 {
                return false;
            }
            break;
        }
    }
    true
}

ffi_export! {
    /// Whether `a`'s numbers and identifiers are all within `b`'s: 1 (also for NULL `a` or `a`
    /// as `b`), or 0 (also if either inherits).
    ///
    /// # Safety
    /// `a` and `b` are NULL or live ASIdentifiers.
    pub unsafe extern "C" fn X509v3_asid_subset(a: *mut ASIdentifiers, b: *mut ASIdentifiers) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        if a.is_null() || a == b {
            return 1;
        }
        if b.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        if unsafe { X509v3_asid_inherits(a) } != 0 || unsafe { X509v3_asid_inherits(b) } != 0 {
            return 0;
        }
        // SAFETY: as above.
        let (ar, br) = (unsafe { &*a }, unsafe { &*b });
        let within = |ac: *mut ASIdentifierChoice, bc: *mut ASIdentifierChoice| {
            // SAFETY: choices of the identifiers, or NULL.
            match (unsafe { ac.as_ref() }, unsafe { bc.as_ref() }) {
                (None, _) => true,
                (Some(_), None) => false,
                (Some(ac), Some(bc)) => as_contains(as_list(bc), as_list(ac)),
            }
        };
        c_int::from(within(ar.asnum, br.asnum) && within(ar.rdi, br.rdi))
    }
}

/// `i2r_ASIdentifierChoice`.
///
/// # Safety
/// `out` is a live BIO.
unsafe fn as_choice_i2r(
    out: *mut BIO,
    choice: *mut ASIdentifierChoice,
    indent: c_int,
    msg: &[u8],
) -> bool {
    // SAFETY: a choice of the identifiers, or NULL.
    let Some(c) = (unsafe { choice.as_ref() }) else {
        return true;
    };
    let inner = indent.saturating_add(2);
    // SAFETY: the caller's BIO.
    unsafe { indent_to(out, indent) };
    // SAFETY: as above.
    unsafe { puts(out, msg) };
    // SAFETY: as above.
    unsafe { puts(out, b":\n") };
    match c.type_ {
        t if t == ASIdentifierChoice_inherit => {
            // SAFETY: as above.
            unsafe { indent_to(out, inner) };
            // SAFETY: as above.
            unsafe { puts(out, b"inherit\n") };
        }
        t if t == ASIdentifierChoice_asIdsOrRanges => {
            let list = as_list(c);
            let text_of = |i: *const ASN1_INTEGER| {
                // SAFETY: an INTEGER of the list, or NULL.
                let s = unsafe { i2s_ASN1_INTEGER(ptr::null_mut(), i) };
                // SAFETY: made above, or NULL.
                let t = unsafe { text(s) }.map(<[u8]>::to_vec);
                // SAFETY: as above.
                unsafe { mem::release(s.cast()) };
                t
            };
            // SAFETY: the list.
            for i in 0..unsafe { OPENSSL_sk_num(list.cast()) } {
                // SAFETY: an index within the list.
                let Some(aor) = (unsafe { at::<ASIdOrRange>(list.cast(), i) }) else {
                    return false;
                };
                match aor.type_ {
                    t if t == ASIdOrRange_id => {
                        // SAFETY: an identifier's member.
                        let Some(s) = text_of(unsafe { aor.u.id }) else {
                            return false;
                        };
                        // SAFETY: as above.
                        unsafe { indent_to(out, inner) };
                        // SAFETY: as above.
                        unsafe { puts(out, &s) };
                        // SAFETY: as above.
                        unsafe { puts(out, b"\n") };
                    }
                    t if t == ASIdOrRange_range => {
                        // SAFETY: a range's member.
                        let r = unsafe { aor.u.range };
                        // SAFETY: the range, or NULL.
                        let Some(r) = (unsafe { r.as_ref() }) else {
                            return false;
                        };
                        let Some(lo) = text_of(r.min) else {
                            return false;
                        };
                        // SAFETY: as above.
                        unsafe { indent_to(out, inner) };
                        // SAFETY: as above.
                        unsafe { puts(out, &lo) };
                        // SAFETY: as above.
                        unsafe { puts(out, b"-") };
                        let Some(hi) = text_of(r.max) else {
                            return false;
                        };
                        // SAFETY: as above.
                        unsafe { puts(out, &hi) };
                        // SAFETY: as above.
                        unsafe { puts(out, b"\n") };
                    }
                    _ => return false,
                }
            }
        }
        _ => return false,
    }
    true
}

ffi_callback! {
    /// `i2r_ASIdentifiers`: the AS numbers, then the routing domain identifiers.
    ///
    /// # Safety
    /// `ext` is live ASIdentifiers; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn asid_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { ext.cast::<ASIdentifiers>().as_ref() }) else { return 0 };
        // SAFETY: the caller's BIO; a choice of the identifiers, or NULL.
        let ok = unsafe { as_choice_i2r(out, a.asnum, indent, b"Autonomous System Numbers") }
            // SAFETY: as above.
            && unsafe { as_choice_i2r(out, a.rdi, indent, b"Routing Domain Identifiers") };
        c_int::from(ok)
    }
}

ffi_callback! {
    /// `v2i_ASIdentifiers`: each `AS` or `RDI` (or `AS.…`, `RDI.…`) as `inherit`, a number, or
    /// a range `min-max`, then put in canonical form.
    ///
    /// # Safety
    /// `values` is NULL or a live stack of `CONF_VALUE`s.
    pub(crate) unsafe extern "C" fn asid_v2i(_method: *const X509V3_EXT_METHOD, _ctx: *mut X509V3_CTX, values: *mut stack_st_CONF_VALUE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        const F: &str = "v2i_ASIdentifiers";
        // SAFETY: no preconditions.
        let asid = unsafe { ASIdentifiers_new() };
        if asid.is_null() {
            err::raise(ERR_LIB_X509V3, ERR_R_X509V3_LIB, F);
            return ptr::null_mut();
        }
        let mut min: *mut ASN1_INTEGER = ptr::null_mut();
        let mut max: *mut ASN1_INTEGER = ptr::null_mut();
        let ok = (|| {
            // SAFETY: the caller's stack, or NULL.
            for i in 0..unsafe { OPENSSL_sk_num(values.cast()) } {
                // SAFETY: an index within the stack.
                let Some(val) = (unsafe { at::<CONF_VALUE>(values.cast(), i) }) else { return false };
                // SAFETY: its name.
                let name = unsafe { text(val.name) };
                let which = if name_is(name, b"AS") {
                    V3_ASID_ASNUM
                } else if name_is(name, b"RDI") {
                    V3_ASID_RDI
                } else {
                    err::raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_NAME_ERROR, F);
                    // SAFETY: the value.
                    unsafe { add_error_name_value(val) };
                    return false;
                };
                // SAFETY: its value.
                let Some(v) = (unsafe { text(val.value) }) else {
                    err::raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR, F);
                    return false;
                };
                if v == b"inherit" {
                    // SAFETY: made above.
                    if unsafe { X509v3_asid_add_inherit(asid, which) } != 0 {
                        continue;
                    }
                    err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_INHERITANCE, F);
                    // SAFETY: the value.
                    unsafe { add_error_name_value(val) };
                    return false;
                }
                const DIGITS: &[u8] = b"0123456789";
                let i1 = span(v, DIGITS);
                if i1 == v.len() {
                    // SAFETY: the value; a slot.
                    if unsafe { X509V3_get_value_int(val, &raw mut min) } == 0 {
                        err::raise(ERR_LIB_X509V3, ERR_R_X509V3_LIB, F);
                        return false;
                    }
                } else {
                    let rest = v.get(i1..).unwrap_or_default();
                    let mut i2 = i1.saturating_add(span(rest, b" \t"));
                    if v.get(i2) != Some(&b'-') {
                        err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_ASNUMBER, F);
                        // SAFETY: the value.
                        unsafe { add_error_name_value(val) };
                        return false;
                    }
                    i2 = i2.saturating_add(1);
                    i2 = i2.saturating_add(span(v.get(i2..).unwrap_or_default(), b" \t"));
                    let i3 = i2.saturating_add(span(v.get(i2..).unwrap_or_default(), DIGITS));
                    if i3 != v.len() {
                        err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_ASRANGE, F);
                        // SAFETY: the value.
                        unsafe { add_error_name_value(val) };
                        return false;
                    }
                    let lo = c_text(v.get(..i1).unwrap_or_default());
                    let hi = c_text(v.get(i2..).unwrap_or_default());
                    // SAFETY: a C string.
                    min = unsafe { s2i_ASN1_INTEGER(ptr::null_mut(), lo.as_ptr().cast()) };
                    // SAFETY: as above.
                    max = unsafe { s2i_ASN1_INTEGER(ptr::null_mut(), hi.as_ptr().cast()) };
                    if min.is_null() || max.is_null() {
                        err::raise(ERR_LIB_X509V3, ERR_R_X509V3_LIB, F);
                        return false;
                    }
                    if icmp(min, max) > 0 {
                        err::raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR, F);
                        return false;
                    }
                }
                // SAFETY: made above; the numbers, which it takes on success.
                if unsafe { X509v3_asid_add_id_or_range(asid, which, min, max) } == 0 {
                    err::raise(ERR_LIB_X509V3, ERR_R_X509V3_LIB, F);
                    return false;
                }
                min = ptr::null_mut();
                max = ptr::null_mut();
            }
            // SAFETY: made above.
            (unsafe { X509v3_asid_canonize(asid) } != 0)
        })();
        if ok {
            return asid.cast();
        }
        // SAFETY: made here, or NULL.
        unsafe { ASIdentifiers_free(asid) };
        // SAFETY: as above.
        unsafe { ASN1_INTEGER_free(min) };
        // SAFETY: as above.
        unsafe { ASN1_INTEGER_free(max) };
        ptr::null_mut()
    }
}

pub(crate) static ASID: Method = Method({
    let mut m = method(NID_sbgp_autonomousSysNum, 0);
    m.it = Some(ASIdentifiers_it);
    m.v2i = Some(asid_v2i);
    m.i2r = Some(asid_i2r);
    m
});

// The IP address blocks (`v3_addr.c`).

static IPRANGE_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(IPAddressRange, min),
        c"min",
        ASN1_BIT_STRING_it,
    ),
    template_at(
        0,
        0,
        offset_of!(IPAddressRange, max),
        c"max",
        ASN1_BIT_STRING_it,
    ),
]);

item_fns! {
    /// IPAddressRange: SEQUENCE { min BIT STRING, max BIT STRING }.
    pub unsafe extern "C" fn IPAddressRange_it = sequence::<IPAddressRange, 2>(&IPRANGE_TT, None, c"IPAddressRange");
}

new_free! {
    pub unsafe extern "C" fn IPAddressRange_new, pub unsafe extern "C" fn IPAddressRange_free(IPAddressRange) = IPAddressRange_it;
}

i2d! {
    /// Encodes an IPAddressRange.
    pub unsafe extern "C" fn i2d_IPAddressRange(IPAddressRange) = IPAddressRange_it;
}

d2i! {
    /// Decodes an IPAddressRange (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_IPAddressRange(IPAddressRange) = IPAddressRange_it;
}

static IPAOR_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(IPAddressOrRange, u),
        c"u.addressPrefix",
        ASN1_BIT_STRING_it,
    ),
    template_at(
        0,
        0,
        offset_of!(IPAddressOrRange, u),
        c"u.addressRange",
        IPAddressRange_it,
    ),
]);

item_fns! {
    /// IPAddressOrRange: CHOICE { addressPrefix BIT STRING, addressRange IPAddressRange }.
    pub unsafe extern "C" fn IPAddressOrRange_it = choice::<IPAddressOrRange, 2>(&IPAOR_TT, offset_of!(IPAddressOrRange, type_), None, c"IPAddressOrRange");
}

new_free! {
    pub unsafe extern "C" fn IPAddressOrRange_new, pub unsafe extern "C" fn IPAddressOrRange_free(IPAddressOrRange) = IPAddressOrRange_it;
}

i2d! {
    /// Encodes an IPAddressOrRange.
    pub unsafe extern "C" fn i2d_IPAddressOrRange(IPAddressOrRange) = IPAddressOrRange_it;
}

d2i! {
    /// Decodes an IPAddressOrRange (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_IPAddressOrRange(IPAddressOrRange) = IPAddressOrRange_it;
}

static IPCHOICE_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(IPAddressChoice, u),
        c"u.inherit",
        ASN1_NULL_it,
    ),
    template_at(
        ASN1_TFLG_SEQUENCE_OF,
        0,
        offset_of!(IPAddressChoice, u),
        c"u.addressesOrRanges",
        IPAddressOrRange_it,
    ),
]);

item_fns! {
    /// IPAddressChoice: CHOICE { inherit NULL, addressesOrRanges SEQUENCE OF IPAddressOrRange }.
    pub unsafe extern "C" fn IPAddressChoice_it = choice::<IPAddressChoice, 2>(&IPCHOICE_TT, offset_of!(IPAddressChoice, type_), None, c"IPAddressChoice");
}

new_free! {
    pub unsafe extern "C" fn IPAddressChoice_new, pub unsafe extern "C" fn IPAddressChoice_free(IPAddressChoice) = IPAddressChoice_it;
}

i2d! {
    /// Encodes an IPAddressChoice.
    pub unsafe extern "C" fn i2d_IPAddressChoice(IPAddressChoice) = IPAddressChoice_it;
}

d2i! {
    /// Decodes an IPAddressChoice (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_IPAddressChoice(IPAddressChoice) = IPAddressChoice_it;
}

static IPFAMILY_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(IPAddressFamily, addressFamily),
        c"addressFamily",
        ASN1_OCTET_STRING_it,
    ),
    template_at(
        0,
        0,
        offset_of!(IPAddressFamily, ipAddressChoice),
        c"ipAddressChoice",
        IPAddressChoice_it,
    ),
]);

item_fns! {
    /// IPAddressFamily: SEQUENCE { addressFamily OCTET STRING, ipAddressChoice IPAddressChoice }.
    pub unsafe extern "C" fn IPAddressFamily_it = sequence::<IPAddressFamily, 2>(&IPFAMILY_TT, None, c"IPAddressFamily");
}

new_free! {
    pub unsafe extern "C" fn IPAddressFamily_new, pub unsafe extern "C" fn IPAddressFamily_free(IPAddressFamily) = IPAddressFamily_it;
}

i2d! {
    /// Encodes an IPAddressFamily.
    pub unsafe extern "C" fn i2d_IPAddressFamily(IPAddressFamily) = IPAddressFamily_it;
}

d2i! {
    /// Decodes an IPAddressFamily (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_IPAddressFamily(IPAddressFamily) = IPAddressFamily_it;
}

static IPADDRBLOCKS_T: Template = template(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    c"IPAddrBlocks",
    IPAddressFamily_it,
);

/// `IPAddrBlocks_it`, which OpenSSL doesn't export.
unsafe extern "C" fn ip_addr_blocks_it() -> *const ASN1_ITEM {
    static ITEM: crate::asn1::tpl::Item = item(
        ASN1_ITYPE_PRIMITIVE,
        -1,
        &raw const IPADDRBLOCKS_T.0,
        0,
        ptr::null(),
        0,
        c"IPAddrBlocks",
    );
    &raw const ITEM.0
}

/// `length_from_afi`: an address's octets in the family.
fn afi_len(afi: c_uint) -> usize {
    match c_int::try_from(afi) {
        Ok(IANA_AFI_IPV4) => 4,
        Ok(IANA_AFI_IPV6) => 16,
        _ => 0,
    }
}

/// A family's identifier octets (its AFI and, optionally, SAFI), or none.
fn family_octets<'a>(f: &IPAddressFamily) -> Option<&'a [u8]> {
    // SAFETY: the family's string, or NULL.
    let s = unsafe { f.addressFamily.as_ref() }?;
    // SAFETY: a live string.
    unsafe { string_octets(s) }
}

/// The unused bits of a BIT STRING's last octet, as OpenSSL reads them (`flags & 7`).
fn unused_bits(bs: &ASN1_BIT_STRING) -> u8 {
    u8::try_from(bs.flags & 7).unwrap_or(0)
}

/// `addr_expand`: a prefix's or bound's octets to `length`, its unused bits and the octets
/// after it all `fill`; `None` if it's longer.
fn expand(bs: *const ASN1_BIT_STRING, length: usize, fill: u8) -> Option<[u8; RAW]> {
    // SAFETY: a BIT STRING of the addresses, or NULL.
    let bs = unsafe { bs.as_ref() }?;
    let n = usize::try_from(bs.length).ok()?;
    if n > length {
        return None;
    }
    let mut addr = [fill; RAW];
    if n > 0 {
        // SAFETY: a string's data holds its length.
        let data = unsafe { octets(bs.data, n) }?;
        addr.get_mut(..n)?.copy_from_slice(data);
        let unused = unused_bits(bs);
        if unused != 0 {
            let mask = 0xFFu8 >> 8u8.saturating_sub(unused);
            let last = addr.get_mut(n.checked_sub(1)?)?;
            if fill == 0 {
                *last &= !mask;
            } else {
                *last |= mask;
            }
        }
    }
    Some(addr)
}

/// `addr_prefixlen`: a prefix's length in bits.
fn prefix_len(bs: &ASN1_BIT_STRING) -> c_int {
    bs.length
        .wrapping_mul(8)
        .wrapping_sub(c_int::from(unused_bits(bs)))
}

/// `memcmp` of the first `length` octets.
fn cmp_n(a: &[u8; RAW], b: &[u8; RAW], length: usize) -> Ordering {
    a.get(..length).cmp(&b.get(..length))
}

/// An ordering as C's comparisons return it.
fn ord(o: Ordering) -> c_int {
    match o {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

/// `addr_expand`'s inputs from an address or range: its prefix or range read from the union.
fn prefix_of(aor: &IPAddressOrRange) -> *mut ASN1_BIT_STRING {
    // SAFETY: both members are pointers.
    unsafe { aor.u.addressPrefix }
}

/// A range's bounds, or `None`.
fn range_of<'a>(aor: &IPAddressOrRange) -> Option<&'a IPAddressRange> {
    // SAFETY: both members are pointers.
    let r = unsafe { aor.u.addressRange };
    // SAFETY: the range, or NULL.
    unsafe { r.as_ref() }
}

/// `extract_min_max`: an address's or range's least and greatest addresses.
fn ip_min_max(aor: Option<&IPAddressOrRange>, length: usize) -> Option<([u8; RAW], [u8; RAW])> {
    let aor = aor?;
    match aor.type_ {
        t if t == IPAddressOrRange_addressPrefix => {
            let p = prefix_of(aor);
            Some((expand(p, length, 0x00)?, expand(p, length, 0xFF)?))
        }
        t if t == IPAddressOrRange_addressRange => {
            let r = range_of(aor)?;
            Some((expand(r.min, length, 0x00)?, expand(r.max, length, 0xFF)?))
        }
        _ => None,
    }
}

/// `IPAddressOrRange_cmp`: by least address, then prefix length (a range as the longest).
fn ip_cmp(a: &IPAddressOrRange, b: &IPAddressOrRange, length: usize) -> c_int {
    let key = |x: &IPAddressOrRange| -> Option<([u8; RAW], c_int)> {
        match x.type_ {
            t if t == IPAddressOrRange_addressPrefix => {
                let p = prefix_of(x);
                let addr = expand(p, length, 0x00)?;
                // SAFETY: the prefix, which `expand` read.
                let len = prefix_len(unsafe { &*p });
                Some((addr, len))
            }
            t if t == IPAddressOrRange_addressRange => {
                let addr = expand(range_of(x)?.min, length, 0x00)?;
                Some((
                    addr,
                    c_int::try_from(length.saturating_mul(8)).unwrap_or(c_int::MAX),
                ))
            }
            _ => None,
        }
    };
    let (Some((aa, la)), Some((ba, lb))) = (key(a), key(b)) else {
        return -1;
    };
    match cmp_n(&aa, &ba, length) {
        Ordering::Equal => la.wrapping_sub(lb),
        o => ord(o),
    }
}

/// A comparison of a stack's addresses of `length` octets.
///
/// # Safety
/// `a` and `b` point to elements of a stack of addresses.
unsafe fn ip_cmp_elems(a: *const c_void, b: *const c_void, length: usize) -> c_int {
    // SAFETY: the caller's guarantee.
    let a = unsafe { *a.cast::<*const IPAddressOrRange>() };
    // SAFETY: as above.
    let b = unsafe { *b.cast::<*const IPAddressOrRange>() };
    // SAFETY: elements of the stack.
    match (unsafe { a.as_ref() }, unsafe { b.as_ref() }) {
        (Some(a), Some(b)) => ip_cmp(a, b, length),
        _ => -1,
    }
}

/// `v4IPAddressOrRange_cmp`.
unsafe extern "C" fn v4_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the stack's guarantee.
    unsafe { ip_cmp_elems(a, b, 4) }
}

/// `v6IPAddressOrRange_cmp`.
unsafe extern "C" fn v6_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the stack's guarantee.
    unsafe { ip_cmp_elems(a, b, 16) }
}

/// `IPAddressFamily_cmp`: by identifier octets, then length.
unsafe extern "C" fn family_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: pointers to the stack's elements.
    let a = unsafe { *a.cast::<*const IPAddressFamily>() };
    // SAFETY: as above.
    let b = unsafe { *b.cast::<*const IPAddressFamily>() };
    // SAFETY: elements of the stack.
    let (Some(a), Some(b)) = (unsafe { a.as_ref() }, unsafe { b.as_ref() }) else {
        return 0;
    };
    let x = family_octets(a).unwrap_or_default();
    let y = family_octets(b).unwrap_or_default();
    let n = x.len().min(y.len());
    match x.get(..n).cmp(&y.get(..n)) {
        Ordering::Equal => {
            let d = i64::try_from(x.len())
                .unwrap_or(0)
                .wrapping_sub(i64::try_from(y.len()).unwrap_or(0));
            ord(d.cmp(&0))
        }
        o => ord(o),
    }
}

/// `range_should_be_prefix`: the prefix length of the range from `min` to `max`, or `None` if
/// it isn't a prefix.
fn range_prefix(min: &[u8; RAW], max: &[u8; RAW], length: usize) -> Option<usize> {
    let at = |a: &[u8; RAW], k: usize| a.get(k).copied().unwrap_or(0);
    let i = (0..length)
        .take_while(|&k| at(min, k) == at(max, k))
        .count();
    let j = (0..length)
        .rev()
        .take_while(|&k| at(min, k) == 0x00 && at(max, k) == 0xFF)
        .count();
    // `j` as OpenSSL's: the last octet that isn't all-zero in min and all-one in max, or -1.
    let j = length.checked_sub(j)?.checked_sub(1);
    match j {
        None => Some(i.saturating_mul(8)),
        Some(j) if i > j => Some(i.saturating_mul(8)),
        Some(j) if i < j => None,
        Some(_) => {
            let mask = at(min, i) ^ at(max, i);
            let bits = match mask {
                0x01 => 7,
                0x03 => 6,
                0x07 => 5,
                0x0F => 4,
                0x1F => 3,
                0x3F => 2,
                0x7F => 1,
                _ => return None,
            };
            if at(min, i) & mask != 0 || at(max, i) & mask != mask {
                None
            } else {
                Some(i.saturating_mul(8).saturating_add(bits))
            }
        }
    }
}

/// `ossl_asn1_string_set_bits_left`.
fn set_bits_left(s: &mut ASN1_BIT_STRING, n: u8) {
    s.flags &= !7;
    s.flags |= core::ffi::c_long::from(ASN1_STRING_FLAG_BITS_LEFT) | core::ffi::c_long::from(n & 7);
}

/// Sets a BIT STRING's octets.
fn set_bits(bs: *mut ASN1_BIT_STRING, data: &[u8]) -> bool {
    let Ok(n) = c_int::try_from(data.len()) else {
        return false;
    };
    // SAFETY: a live BIT STRING; the octets, copied.
    (unsafe { ASN1_BIT_STRING_set(bs, data.as_ptr().cast_mut(), n) } != 0)
}

/// `make_addressPrefix`: a new prefix of `prefixlen` bits from `addr`, or NULL.
fn make_prefix(addr: &[u8], prefixlen: c_int, afilen: usize) -> *mut IPAddressOrRange {
    let Ok(plen) = usize::try_from(prefixlen) else {
        return ptr::null_mut();
    };
    if plen > afilen.saturating_mul(8) {
        return ptr::null_mut();
    }
    let bytelen = plen.div_ceil(8);
    let bitlen = u8::try_from(plen % 8).unwrap_or(0);
    let Some(data) = addr.get(..bytelen) else {
        return ptr::null_mut();
    };
    // The bits after the prefix are zero.
    let mut data = data.to_vec();
    if bitlen > 0
        && let Some(last) = data.last_mut()
    {
        *last &= !(0xFFu8 >> bitlen);
    }
    // SAFETY: no preconditions.
    let aor = unsafe { IPAddressOrRange_new() };
    // SAFETY: new, or NULL.
    let Some(a) = (unsafe { aor.as_mut() }) else {
        return ptr::null_mut();
    };
    let fail = || {
        // SAFETY: made above.
        unsafe { IPAddressOrRange_free(aor) };
        ptr::null_mut()
    };
    a.type_ = IPAddressOrRange_addressPrefix;
    if prefix_of(a).is_null() {
        // SAFETY: no preconditions.
        a.u.addressPrefix = unsafe { ASN1_BIT_STRING_new() };
        if prefix_of(a).is_null() {
            return fail();
        }
    }
    let p = prefix_of(a);
    if !set_bits(p, &data) {
        return fail();
    }
    // SAFETY: the prefix, set above.
    let ps = unsafe { &mut *p };
    set_bits_left(ps, 8u8.wrapping_sub(bitlen));
    aor
}

/// `make_addressRange`: a new range from `min` to `max` (a prefix if it is one), or NULL.
fn make_range(min: &[u8; RAW], max: &[u8; RAW], length: usize) -> *mut IPAddressOrRange {
    if cmp_n(min, max, length) == Ordering::Greater {
        return ptr::null_mut();
    }
    if let Some(p) = range_prefix(min, max, length) {
        let Ok(p) = c_int::try_from(p) else {
            return ptr::null_mut();
        };
        return make_prefix(min, p, length);
    }
    // SAFETY: no preconditions.
    let aor = unsafe { IPAddressOrRange_new() };
    // SAFETY: new, or NULL.
    let Some(a) = (unsafe { aor.as_mut() }) else {
        return ptr::null_mut();
    };
    let fail = || {
        // SAFETY: made above.
        unsafe { IPAddressOrRange_free(aor) };
        ptr::null_mut()
    };
    a.type_ = IPAddressOrRange_addressRange;
    // SAFETY: no preconditions.
    let r = unsafe { IPAddressRange_new() };
    a.u.addressRange = r;
    // SAFETY: new, or NULL.
    let Some(rr) = (unsafe { r.as_mut() }) else {
        return fail();
    };
    for bound in [&mut rr.min, &mut rr.max] {
        if bound.is_null() {
            // SAFETY: no preconditions.
            *bound = unsafe { ASN1_BIT_STRING_new() };
            if bound.is_null() {
                return fail();
            }
        }
    }
    let at = |a: &[u8; RAW], k: usize| a.get(k).copied().unwrap_or(0);
    // The least address without its trailing zero octets, the last one's trailing zero bits
    // unused; the greatest without its trailing all-one octets, likewise.
    for (bound, addr, trail) in [(rr.min, min, 0x00u8), (rr.max, max, 0xFFu8)] {
        let i = length.saturating_sub(
            (0..length)
                .rev()
                .take_while(|&k| at(addr, k) == trail)
                .count(),
        );
        if !set_bits(bound, addr.get(..i).unwrap_or_default()) {
            return fail();
        }
        // SAFETY: the bound, set above.
        let bs = unsafe { &mut *bound };
        set_bits_left(bs, 0);
        if let Some(last) = i.checked_sub(1) {
            let b = u32::from(at(addr, last));
            let mut j = 1u32;
            let want = |j: u32| if trail == 0 { 0 } else { 0xFFu32 >> j };
            while j < 8 && (b & (0xFFu32 >> j)) != want(j) {
                j = j.saturating_add(1);
            }
            bs.flags |= core::ffi::c_long::from(8u8.saturating_sub(u8::try_from(j).unwrap_or(8)));
        }
    }
    aor
}

/// `make_IPAddressFamily`: the family of `afi` (and `safi`) in `addr`, added if absent, or
/// NULL.
///
/// # Safety
/// `addr` is a live stack of families; `safi` is NULL or readable.
unsafe fn family(
    addr: *mut IPAddrBlocks,
    afi: c_uint,
    safi: *const c_uint,
) -> *mut IPAddressFamily {
    let [_, _, hi, lo] = afi.to_be_bytes();
    let mut key = vec![hi, lo];
    // SAFETY: the caller's guarantee.
    if let Some(&s) = unsafe { safi.as_ref() } {
        key.push(s.to_be_bytes()[3]);
    }
    // SAFETY: the caller's stack.
    for i in 0..unsafe { OPENSSL_sk_num(addr.cast()) } {
        // SAFETY: an index within the stack.
        let Some(f) = (unsafe { at::<IPAddressFamily>(addr.cast(), i) }) else {
            continue;
        };
        if family_octets(f) == Some(&key[..]) {
            return f;
        }
    }
    // SAFETY: no preconditions.
    let f = unsafe { IPAddressFamily_new() };
    // SAFETY: new, or NULL.
    let Some(fr) = (unsafe { f.as_mut() }) else {
        return ptr::null_mut();
    };
    let fail = || {
        // SAFETY: made above.
        unsafe { IPAddressFamily_free(f) };
        ptr::null_mut()
    };
    if fr.ipAddressChoice.is_null() {
        // SAFETY: no preconditions.
        fr.ipAddressChoice = unsafe { IPAddressChoice_new() };
        if fr.ipAddressChoice.is_null() {
            return fail();
        }
    }
    if fr.addressFamily.is_null() {
        // SAFETY: no preconditions.
        fr.addressFamily = unsafe { ASN1_OCTET_STRING_new() };
        if fr.addressFamily.is_null() {
            return fail();
        }
    }
    let Ok(n) = c_int::try_from(key.len()) else {
        return fail();
    };
    // SAFETY: the family's string; the key.
    if unsafe { ASN1_OCTET_STRING_set(fr.addressFamily, key.as_ptr(), n) } == 0 {
        return fail();
    }
    // SAFETY: the caller's stack; the family, which it takes.
    if unsafe { OPENSSL_sk_push(addr.cast(), f.cast()) } == 0 {
        return fail();
    }
    f
}

/// The addresses of a choice, read from the union whatever its type.
fn ip_list(c: &IPAddressChoice) -> *mut IPAddressOrRanges {
    // SAFETY: both members are pointers.
    unsafe { c.u.addressesOrRanges }
}

ffi_export! {
    /// Makes the family of `afi` (and `safi`, if not NULL) inherit, adding it if absent: 1, or
    /// 0 if it lists addresses.
    ///
    /// # Safety
    /// `addr` is a live stack of families; `safi` is NULL or readable.
    pub unsafe extern "C" fn X509v3_addr_add_inherit(addr: *mut IPAddrBlocks, afi: c_uint, safi: *const c_uint) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let f = unsafe { family(addr, afi, safi) };
        // SAFETY: the family, or NULL.
        let Some(f) = (unsafe { f.as_mut() }) else { return 0 };
        // SAFETY: its choice, or NULL.
        let Some(c) = (unsafe { f.ipAddressChoice.as_mut() }) else { return 0 };
        if c.type_ == IPAddressChoice_addressesOrRanges && !ip_list(c).is_null() {
            return 0;
        }
        // SAFETY: both members are pointers.
        let inherit = unsafe { c.u.inherit };
        if c.type_ == IPAddressChoice_inherit && !inherit.is_null() {
            return 1;
        }
        if inherit.is_null() {
            // SAFETY: no preconditions.
            let null = unsafe { ASN1_NULL_new() };
            if null.is_null() {
                return 0;
            }
            c.u.inherit = null;
        }
        c.type_ = IPAddressChoice_inherit;
        1
    }
}

/// `make_prefix_or_range`: the address list of the family of `afi` (and `safi`), made if
/// absent, or NULL if it inherits.
///
/// # Safety
/// As for [`family`].
unsafe fn prefix_or_range(
    addr: *mut IPAddrBlocks,
    afi: c_uint,
    safi: *const c_uint,
) -> *mut IPAddressOrRanges {
    // SAFETY: the caller's guarantee.
    let f = unsafe { family(addr, afi, safi) };
    // SAFETY: the family, or NULL.
    let Some(f) = (unsafe { f.as_mut() }) else {
        return ptr::null_mut();
    };
    // SAFETY: its choice, or NULL.
    let Some(c) = (unsafe { f.ipAddressChoice.as_mut() }) else {
        return ptr::null_mut();
    };
    // SAFETY: both members are pointers.
    if c.type_ == IPAddressChoice_inherit && !unsafe { c.u.inherit }.is_null() {
        return ptr::null_mut();
    }
    if c.type_ == IPAddressChoice_addressesOrRanges && !ip_list(c).is_null() {
        return ip_list(c);
    }
    // SAFETY: no preconditions.
    let aors = unsafe { OPENSSL_sk_new_null() };
    if aors.is_null() {
        return ptr::null_mut();
    }
    let cmp: rustyssl_abi::OPENSSL_sk_compfunc = match afi_len(afi) {
        4 => Some(v4_cmp),
        16 => Some(v6_cmp),
        _ => None,
    };
    if cmp.is_some() {
        // SAFETY: the new list; a comparison of its elements.
        unsafe { OPENSSL_sk_set_cmp_func(aors, cmp) };
    }
    c.type_ = IPAddressChoice_addressesOrRanges;
    c.u.addressesOrRanges = aors.cast();
    aors.cast()
}

/// Adds an address or range to a list, freeing it if that fails.
fn push_aor(aors: *mut IPAddressOrRanges, aor: *mut IPAddressOrRange) -> c_int {
    // SAFETY: the list; the address, which it takes.
    if unsafe { OPENSSL_sk_push(aors.cast(), aor.cast()) } != 0 {
        return 1;
    }
    // SAFETY: the caller's new address.
    unsafe { IPAddressOrRange_free(aor) };
    0
}

ffi_export! {
    /// Adds the prefix of `prefixlen` bits at `a` to the family of `afi` (and `safi`): 1, or 0
    /// (also if the family inherits).
    ///
    /// # Safety
    /// `addr` is a live stack of families; `safi` is NULL or readable; `a` holds the prefix's
    /// octets.
    pub unsafe extern "C" fn X509v3_addr_add_prefix(addr: *mut IPAddrBlocks, afi: c_uint, safi: *const c_uint, a: *mut c_uchar, prefixlen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let aors = unsafe { prefix_or_range(addr, afi, safi) };
        if aors.is_null() {
            return 0;
        }
        let length = afi_len(afi);
        let Ok(plen) = usize::try_from(prefixlen) else { return 0 };
        if plen > length.saturating_mul(8) {
            return 0;
        }
        // SAFETY: the caller's prefix holds its octets.
        let Some(octs) = (unsafe { octets(a, plen.div_ceil(8)) }) else { return 0 };
        let aor = make_prefix(octs, prefixlen, length);
        if aor.is_null() {
            return 0;
        }
        push_aor(aors, aor)
    }
}

/// The first `length` octets at `p` as an address, or `None` for NULL.
///
/// # Safety
/// `p` is NULL or holds `length` octets.
unsafe fn raw_addr(p: *const c_uchar, length: usize) -> Option<[u8; RAW]> {
    // SAFETY: the caller's guarantee.
    let s = unsafe { octets(p, length) }?;
    let mut a = [0u8; RAW];
    a.get_mut(..length)?.copy_from_slice(s);
    Some(a)
}

ffi_export! {
    /// Adds the range from `min` to `max` (a prefix if it is one) to the family of `afi` (and
    /// `safi`): 1, or 0.
    ///
    /// # Safety
    /// `addr` is a live stack of families; `safi` is NULL or readable; `min` and `max` hold an
    /// address of the family.
    pub unsafe extern "C" fn X509v3_addr_add_range(addr: *mut IPAddrBlocks, afi: c_uint, safi: *const c_uint, min: *mut c_uchar, max: *mut c_uchar) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let aors = unsafe { prefix_or_range(addr, afi, safi) };
        if aors.is_null() {
            return 0;
        }
        let length = afi_len(afi);
        // SAFETY: the caller's addresses.
        let (Some(lo), Some(hi)) = (unsafe { raw_addr(min, length) }, unsafe { raw_addr(max, length) }) else { return 0 };
        let aor = make_range(&lo, &hi, length);
        if aor.is_null() {
            return 0;
        }
        push_aor(aors, aor)
    }
}

ffi_export! {
    /// The family's AFI (its first two octets), or 0.
    ///
    /// # Safety
    /// `f` is NULL or a live family.
    pub unsafe extern "C" fn X509v3_addr_get_afi(f: *const IPAddressFamily) -> c_uint
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(f) = (unsafe { f.as_ref() }) else { return 0 };
        // SAFETY: its string, or NULL.
        let Some(s) = (unsafe { f.addressFamily.as_ref() }) else { return 0 };
        if s.data.is_null() || s.length < 2 {
            return 0;
        }
        // SAFETY: a string's data holds its length, at least 2.
        let Some(&[hi, lo, ..]) = (unsafe { string_octets(s) }) else { return 0 };
        c_uint::from(u16::from_be_bytes([hi, lo]))
    }
}

ffi_export! {
    /// Writes the least and greatest addresses of the prefix or range, `afi`'s length, to `min`
    /// and `max`: that length, or 0 (also if `length` is shorter).
    ///
    /// # Safety
    /// `aor` is NULL or a live address or range; `min` and `max` are NULL or hold `length`
    /// octets.
    pub unsafe extern "C" fn X509v3_addr_get_range(aor: *mut IPAddressOrRange, afi: c_uint, min: *mut c_uchar, max: *mut c_uchar, length: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        let afilen = afi_len(afi);
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { aor.as_ref() }) else { return 0 };
        let room = usize::try_from(length).unwrap_or(0);
        if min.is_null() || max.is_null() || afilen == 0 || room < afilen {
            return 0;
        }
        if a.type_ != IPAddressOrRange_addressPrefix && a.type_ != IPAddressOrRange_addressRange {
            return 0;
        }
        let Some((lo, hi)) = ip_min_max(Some(a), afilen) else { return 0 };
        for (dst, src) in [(min, lo), (max, hi)] {
            // SAFETY: the caller's buffer holds `length` octets, at least `afilen`.
            let d = unsafe { core::slice::from_raw_parts_mut(dst, afilen) };
            d.copy_from_slice(src.get(..afilen).unwrap_or_default());
        }
        c_int::try_from(afilen).unwrap_or(0)
    }
}

/// `IPAddressFamily_check_len`: two or three identifier octets.
fn family_len_ok(f: &IPAddressFamily) -> bool {
    // SAFETY: the family's string, or NULL.
    unsafe { f.addressFamily.as_ref() }.is_some_and(|s| (2..=3).contains(&s.length))
}

/// The family's address length.
fn family_addr_len(f: *const IPAddressFamily) -> usize {
    // SAFETY: a family, or NULL.
    afi_len(unsafe { X509v3_addr_get_afi(f) })
}

/// `b_min - 1`, as OpenSSL's borrowing loop computes it.
fn minus_one(a: &mut [u8; RAW], length: usize) {
    for k in (0..length).rev() {
        let Some(x) = a.get_mut(k) else { return };
        let was = *x;
        *x = was.wrapping_sub(1);
        if was != 0 {
            return;
        }
    }
}

ffi_export! {
    /// Whether the address blocks are in canonical form: 1 (also for NULL), or 0.
    ///
    /// # Safety
    /// `addr` is NULL or a live stack of families.
    pub unsafe extern "C" fn X509v3_addr_is_canonical(addr: *mut IPAddrBlocks) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        if addr.is_null() {
            return 1;
        }
        // SAFETY: the caller's stack.
        let n = unsafe { OPENSSL_sk_num(addr.cast()) };
        for i in 0..n.saturating_sub(1) {
            // SAFETY: indices within the stack.
            let a = unsafe { OPENSSL_sk_value(addr.cast(), i) };
            // SAFETY: as above.
            let b = unsafe { OPENSSL_sk_value(addr.cast(), i.wrapping_add(1)) };
            // SAFETY: families of the stack, or NULL.
            let (Some(fa), Some(fb)) = (unsafe { a.cast::<IPAddressFamily>().as_ref() }, unsafe { b.cast::<IPAddressFamily>().as_ref() }) else {
                return 0;
            };
            if !family_len_ok(fa) || !family_len_ok(fb) {
                return 0;
            }
            // SAFETY: pointers to the two families.
            if unsafe { family_cmp((&raw const a).cast(), (&raw const b).cast()) } >= 0 {
                return 0;
            }
        }
        for i in 0..n {
            // SAFETY: an index within the stack.
            let fp = unsafe { OPENSSL_sk_value(addr.cast(), i) }.cast::<IPAddressFamily>();
            let length = family_addr_len(fp);
            // SAFETY: a family of the stack, or NULL.
            let Some(f) = (unsafe { fp.as_ref() }) else { return 0 };
            // SAFETY: its choice, or NULL.
            let Some(c) = (unsafe { f.ipAddressChoice.as_ref() }) else { return 0 };
            match c.type_ {
                t if t == IPAddressChoice_inherit => continue,
                t if t == IPAddressChoice_addressesOrRanges => {}
                _ => return 0,
            }
            if !family_len_ok(f) {
                return 0;
            }
            let aors = ip_list(c);
            // SAFETY: the list, or NULL.
            let m = unsafe { OPENSSL_sk_num(aors.cast()) };
            if m == 0 {
                return 0;
            }
            for j in 0..m.saturating_sub(1) {
                // SAFETY: indices within the list.
                let a = unsafe { at::<IPAddressOrRange>(aors.cast(), j) }.map(|x| &*x);
                // SAFETY: as above.
                let b = unsafe { at::<IPAddressOrRange>(aors.cast(), j.wrapping_add(1)) }.map(|x| &*x);
                let (Some((amin, amax)), Some((mut bmin, bmax))) = (ip_min_max(a, length), ip_min_max(b, length)) else {
                    return 0;
                };
                if cmp_n(&amin, &bmin, length) != Ordering::Less
                    || cmp_n(&amin, &amax, length) == Ordering::Greater
                    || cmp_n(&bmin, &bmax, length) == Ordering::Greater
                {
                    return 0;
                }
                minus_one(&mut bmin, length);
                if cmp_n(&amax, &bmin, length) != Ordering::Less {
                    return 0;
                }
                if a.is_some_and(|a| a.type_ == IPAddressOrRange_addressRange)
                    && range_prefix(&amin, &amax, length).is_some()
                {
                    return 0;
                }
            }
            // SAFETY: an index within the list, or none.
            let last = unsafe { at::<IPAddressOrRange>(aors.cast(), m.wrapping_sub(1)) };
            if let Some(a) = last
                && a.type_ == IPAddressOrRange_addressRange
            {
                let Some((amin, amax)) = ip_min_max(Some(a), length) else { return 0 };
                if cmp_n(&amin, &amax, length) == Ordering::Greater || range_prefix(&amin, &amax, length).is_some() {
                    return 0;
                }
            }
        }
        1
    }
}

/// `IPAddressOrRanges_canonize`.
fn ip_canonize(aors: *mut IPAddressOrRanges, afi: c_uint) -> bool {
    let length = afi_len(afi);
    // SAFETY: the list (sorted only if it has a comparison), or NULL.
    unsafe { OPENSSL_sk_sort(aors.cast()) };
    let mut i: c_int = 0;
    // SAFETY: the list, or NULL.
    while i < unsafe { OPENSSL_sk_num(aors.cast()) }.saturating_sub(1) {
        // SAFETY: indices within the list.
        let a = unsafe { OPENSSL_sk_value(aors.cast(), i) }.cast::<IPAddressOrRange>();
        // SAFETY: as above.
        let b =
            unsafe { OPENSSL_sk_value(aors.cast(), i.wrapping_add(1)) }.cast::<IPAddressOrRange>();
        // SAFETY: elements of the list, or NULL.
        let (ar, br) = (unsafe { a.as_ref() }, unsafe { b.as_ref() });
        let (Some((amin, amax)), Some((mut bmin, bmax))) =
            (ip_min_max(ar, length), ip_min_max(br, length))
        else {
            return false;
        };
        if cmp_n(&amin, &amax, length) == Ordering::Greater
            || cmp_n(&bmin, &bmax, length) == Ordering::Greater
        {
            return false;
        }
        if cmp_n(&amax, &bmin, length) != Ordering::Less {
            return false;
        }
        minus_one(&mut bmin, length);
        if cmp_n(&amax, &bmin, length) == Ordering::Equal {
            let merged = make_range(&amin, &bmax, length);
            if merged.is_null() {
                return false;
            }
            // SAFETY: the list; an index within it; the merged range, which it takes.
            unsafe { OPENSSL_sk_set(aors.cast(), i, merged.cast()) };
            // SAFETY: as above.
            unsafe { OPENSSL_sk_delete(aors.cast(), i.wrapping_add(1)) };
            // SAFETY: the two replaced elements.
            unsafe { IPAddressOrRange_free(a) };
            // SAFETY: as above.
            unsafe { IPAddressOrRange_free(b) };
            continue;
        }
        i = i.wrapping_add(1);
    }
    // SAFETY: the list, or NULL.
    let n = unsafe { OPENSSL_sk_num(aors.cast()) };
    // SAFETY: an index within the list, or none.
    if let Some(a) = unsafe { at::<IPAddressOrRange>(aors.cast(), n.wrapping_sub(1)) }
        && a.type_ == IPAddressOrRange_addressRange
    {
        match ip_min_max(Some(a), length) {
            Some((amin, amax)) if cmp_n(&amin, &amax, length) != Ordering::Greater => {}
            _ => return false,
        }
    }
    true
}

ffi_export! {
    /// Puts the address blocks in canonical form: each list sorted (if it has a comparison)
    /// with adjacent entries merged, and the families sorted: 1, or 0 for an overlap, a family
    /// of the wrong length, or NULL (`X509V3_R_INVALID_NULL_ARGUMENT`).
    ///
    /// # Safety
    /// `addr` is NULL or a live stack of families.
    pub unsafe extern "C" fn X509v3_addr_canonize(addr: *mut IPAddrBlocks) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        if addr.is_null() {
            err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_NULL_ARGUMENT, "X509v3_addr_canonize");
            return 0;
        }
        // SAFETY: the caller's stack.
        for i in 0..unsafe { OPENSSL_sk_num(addr.cast()) } {
            // SAFETY: an index within the stack.
            let fp = unsafe { OPENSSL_sk_value(addr.cast(), i) }.cast::<IPAddressFamily>();
            // SAFETY: a family of the stack, or NULL.
            let Some(f) = (unsafe { fp.as_ref() }) else { return 0 };
            if !family_len_ok(f) {
                return 0;
            }
            // SAFETY: its choice, or NULL.
            let Some(c) = (unsafe { f.ipAddressChoice.as_ref() }) else { return 0 };
            if c.type_ == IPAddressChoice_addressesOrRanges {
                // SAFETY: the family.
                let afi = unsafe { X509v3_addr_get_afi(fp) };
                if !ip_canonize(ip_list(c), afi) {
                    return 0;
                }
            }
        }
        // SAFETY: the stack; a comparison of its families.
        unsafe { OPENSSL_sk_set_cmp_func(addr.cast(), Some(family_cmp)) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_sort(addr.cast()) };
        // SAFETY: as above.
        c_int::from(unsafe { X509v3_addr_is_canonical(addr) } != 0)
    }
}

ffi_export! {
    /// Whether any family inherits: 1, or 0.
    ///
    /// # Safety
    /// `addr` is NULL or a live stack of families.
    pub unsafe extern "C" fn X509v3_addr_inherits(addr: *mut IPAddrBlocks) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's stack, or NULL.
        for i in 0..unsafe { OPENSSL_sk_num(addr.cast()) } {
            // SAFETY: an index within the stack.
            let Some(f) = (unsafe { at::<IPAddressFamily>(addr.cast(), i) }) else { continue };
            // SAFETY: its choice, or NULL.
            if unsafe { f.ipAddressChoice.as_ref() }.is_some_and(|c| c.type_ == IPAddressChoice_inherit) {
                return 1;
            }
        }
        0
    }
}

/// `addr_contains`: whether every entry of `child` is within one of `parent`'s.
fn ip_contains(
    parent: *mut IPAddressOrRanges,
    child: *mut IPAddressOrRanges,
    length: usize,
) -> bool {
    if child.is_null() || parent == child {
        return true;
    }
    if parent.is_null() {
        return false;
    }
    let mut p: c_int = 0;
    // SAFETY: the lists.
    let (nc, np) = (unsafe { OPENSSL_sk_num(child.cast()) }, unsafe {
        OPENSSL_sk_num(parent.cast())
    });
    for c in 0..nc {
        // SAFETY: an index within the child.
        let Some((cmin, cmax)) = ip_min_max(
            unsafe { at::<IPAddressOrRange>(child.cast(), c) }.map(|x| &*x),
            length,
        ) else {
            return false;
        };
        loop {
            if p >= np {
                return false;
            }
            // SAFETY: an index within the parent.
            let Some((pmin, pmax)) = ip_min_max(
                unsafe { at::<IPAddressOrRange>(parent.cast(), p) }.map(|x| &*x),
                length,
            ) else {
                return false;
            };
            if cmp_n(&pmax, &cmax, length) == Ordering::Less {
                p = p.wrapping_add(1);
                continue;
            }
            if cmp_n(&pmin, &cmin, length) == Ordering::Greater {
                return false;
            }
            break;
        }
    }
    true
}

ffi_export! {
    /// Whether `a`'s addresses are all within `b`'s, family by family: 1 (also for NULL `a` or
    /// `a` as `b`), or 0 (also if either inherits). Sorts `b`'s families, as OpenSSL does.
    ///
    /// # Safety
    /// `a` and `b` are NULL or live stacks of families.
    pub unsafe extern "C" fn X509v3_addr_subset(a: *mut IPAddrBlocks, b: *mut IPAddrBlocks) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        if a.is_null() || a == b {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        if b.is_null() || unsafe { X509v3_addr_inherits(a) } != 0 || unsafe { X509v3_addr_inherits(b) } != 0 {
            return 0;
        }
        // SAFETY: as above; a comparison of its families.
        unsafe { OPENSSL_sk_set_cmp_func(b.cast(), Some(family_cmp)) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_sort(b.cast()) };
        // SAFETY: as above.
        for i in 0..unsafe { OPENSSL_sk_num(a.cast()) } {
            // SAFETY: an index within `a`.
            let fa = unsafe { OPENSSL_sk_value(a.cast(), i) };
            // SAFETY: `b`, sorted; a family to find.
            let j = unsafe { OPENSSL_sk_find(b.cast(), fa) };
            // SAFETY: an index within `b`, or -1.
            let fb = unsafe { OPENSSL_sk_value(b.cast(), j) }.cast::<IPAddressFamily>();
            // SAFETY: families of the stacks, or NULL.
            let (Some(far), Some(fbr)) = (unsafe { fa.cast::<IPAddressFamily>().as_ref() }, unsafe { fb.as_ref() }) else {
                return 0;
            };
            if !family_len_ok(far) || !family_len_ok(fbr) {
                return 0;
            }
            // SAFETY: their choices, or NULL.
            let (Some(ca), Some(cb)) = (unsafe { far.ipAddressChoice.as_ref() }, unsafe { fbr.ipAddressChoice.as_ref() }) else {
                return 0;
            };
            if !ip_contains(ip_list(cb), ip_list(ca), family_addr_len(fb)) {
                return 0;
            }
        }
        1
    }
}

/// `i2r_address`: an address (`fill` for its unused bits and missing octets) as text.
///
/// # Safety
/// `out` is a live BIO.
unsafe fn address_i2r(out: *mut BIO, afi: c_uint, fill: u8, bs: *const ASN1_BIT_STRING) -> bool {
    // SAFETY: a BIT STRING of the addresses, or NULL.
    let Some(b) = (unsafe { bs.as_ref() }) else {
        return false;
    };
    if b.length < 0 {
        return false;
    }
    let s = match afi_len(afi) {
        4 => {
            let Some(a) = expand(bs, 4, fill) else {
                return false;
            };
            let [w, x, y, z, ..] = a;
            format!("{w}.{x}.{y}.{z}")
        }
        16 => {
            let Some(a) = expand(bs, 16, fill) else {
                return false;
            };
            let groups = a.as_chunks::<2>().0;
            let mut n = groups.len();
            while n > 0 && groups.get(n.wrapping_sub(1)) == Some(&[0, 0]) {
                n = n.wrapping_sub(1);
            }
            let mut s = String::new();
            for (i, g) in groups.iter().take(n).enumerate() {
                s.push_str(&format!("{:x}", u16::from_be_bytes(*g)));
                if i < 7 {
                    s.push(':');
                }
            }
            if n < 8 {
                s.push(':');
            }
            if n == 0 {
                s.push(':');
            }
            s
        }
        _ => {
            let n = usize::try_from(b.length).unwrap_or(0);
            // SAFETY: a string's data holds its length.
            let data = unsafe { octets(b.data, n) }.unwrap_or_default();
            let mut s = String::new();
            for (i, o) in data.iter().enumerate() {
                if i > 0 {
                    s.push(':');
                }
                s.push_str(&format!("{o:02x}"));
            }
            s.push_str(&format!("[{}]", unused_bits(b)));
            s
        }
    };
    // SAFETY: the caller's BIO.
    unsafe { puts(out, s.as_bytes()) };
    true
}

/// `i2r_IPAddressOrRanges`: each prefix (`address/length`) or range (`min-max`) on a line.
///
/// # Safety
/// `out` is a live BIO.
unsafe fn ranges_i2r(
    out: *mut BIO,
    indent: c_int,
    aors: *mut IPAddressOrRanges,
    afi: c_uint,
) -> bool {
    // SAFETY: the list, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(aors.cast()) } {
        // SAFETY: an index within the list.
        let Some(aor) = (unsafe { at::<IPAddressOrRange>(aors.cast(), i) }) else {
            return false;
        };
        // SAFETY: the caller's BIO.
        unsafe { indent_to(out, indent) };
        match aor.type_ {
            t if t == IPAddressOrRange_addressPrefix => {
                let p = prefix_of(aor);
                // SAFETY: as above.
                if !unsafe { address_i2r(out, afi, 0x00, p) } {
                    return false;
                }
                // SAFETY: the prefix, which `address_i2r` read.
                let len = prefix_len(unsafe { &*p });
                // SAFETY: as above.
                unsafe { puts(out, format!("/{len}\n").as_bytes()) };
            }
            t if t == IPAddressOrRange_addressRange => {
                let Some(r) = range_of(aor) else { return false };
                // SAFETY: as above.
                if !unsafe { address_i2r(out, afi, 0x00, r.min) } {
                    return false;
                }
                // SAFETY: as above.
                unsafe { puts(out, b"-") };
                // SAFETY: as above.
                if !unsafe { address_i2r(out, afi, 0xFF, r.max) } {
                    return false;
                }
                // SAFETY: as above.
                unsafe { puts(out, b"\n") };
            }
            _ => {}
        }
    }
    true
}

/// The name OpenSSL prints for a SAFI.
fn safi_name(safi: u8) -> Option<&'static [u8]> {
    Some(match safi {
        1 => b" (Unicast)",
        2 => b" (Multicast)",
        3 => b" (Unicast/Multicast)",
        4 => b" (MPLS)",
        64 => b" (Tunnel)",
        65 => b" (VPLS)",
        66 => b" (BGP MDT)",
        128 => b" (MPLS-labeled VPN)",
        _ => return None,
    })
}

ffi_callback! {
    /// `i2r_IPAddrBlocks`: each family (`IPv4`, `IPv6`, or `Unknown AFI`, with its SAFI), then
    /// `inherit` or its addresses.
    ///
    /// # Safety
    /// `ext` is a live stack of families; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn addr_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's stack.
        for i in 0..unsafe { OPENSSL_sk_num(ext.cast()) } {
            // SAFETY: an index within the stack.
            let fp = unsafe { OPENSSL_sk_value(ext.cast(), i) }.cast::<IPAddressFamily>();
            // SAFETY: a family of the stack, or NULL.
            let Some(f) = (unsafe { fp.as_ref() }) else { return 0 };
            // SAFETY: as above.
            let afi = unsafe { X509v3_addr_get_afi(fp) };
            // SAFETY: the caller's BIO.
            unsafe { indent_to(out, indent) };
            let head = match afi_len(afi) {
                4 => "IPv4".to_owned(),
                16 => "IPv6".to_owned(),
                _ => format!("Unknown AFI {afi}"),
            };
            // SAFETY: as above.
            unsafe { puts(out, head.as_bytes()) };
            if let Some(&safi) = family_octets(f).and_then(|o| o.get(2)) {
                match safi_name(safi) {
                    // SAFETY: as above.
                    Some(n) => unsafe { puts(out, n) },
                    // SAFETY: as above.
                    None => unsafe { puts(out, format!(" (Unknown SAFI {safi})").as_bytes()) },
                }
            }
            // SAFETY: its choice, or NULL.
            let Some(c) = (unsafe { f.ipAddressChoice.as_ref() }) else { return 0 };
            match c.type_ {
                // SAFETY: as above.
                t if t == IPAddressChoice_inherit => unsafe { puts(out, b": inherit\n") },
                t if t == IPAddressChoice_addressesOrRanges => {
                    // SAFETY: as above.
                    unsafe { puts(out, b":\n") };
                    // SAFETY: as above.
                    if !unsafe { ranges_i2r(out, indent.saturating_add(2), ip_list(c), afi) } {
                        return 0;
                    }
                }
                _ => {}
            }
        }
        1
    }
}

/// Raises `reason` with the value's name and value as data.
///
/// # Safety
/// `val` is a live `CONF_VALUE`.
unsafe fn value_err(reason: c_int, val: &CONF_VALUE, f: &str) {
    err::raise(ERR_LIB_X509V3, reason, f);
    // SAFETY: the caller's guarantee.
    unsafe { add_error_name_value(val) };
}

ffi_callback! {
    /// `v2i_IPAddrBlocks`: each `IPv4`, `IPv6`, `IPv4-SAFI`, or `IPv6-SAFI` (the SAFI then
    /// `:` first) as `inherit`, an address, a prefix `address/length`, or a range `min-max`,
    /// then put in canonical form.
    ///
    /// # Safety
    /// `values` is NULL or a live stack of `CONF_VALUE`s.
    pub(crate) unsafe extern "C" fn addr_v2i(_method: *const X509V3_EXT_METHOD, _ctx: *mut X509V3_CTX, values: *mut stack_st_CONF_VALUE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        const F: &str = "v2i_IPAddrBlocks";
        const V4: &[u8] = b"0123456789.";
        const V6: &[u8] = b"0123456789.:abcdefABCDEF";
        // SAFETY: a comparison of its families.
        let addr = unsafe { OPENSSL_sk_new(Some(family_cmp)) }.cast::<IPAddrBlocks>();
        if addr.is_null() {
            err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, F);
            return ptr::null_mut();
        }
        let ok = (|| {
            // SAFETY: the caller's stack, or NULL.
            for i in 0..unsafe { OPENSSL_sk_num(values.cast()) } {
                // SAFETY: an index within the stack.
                let Some(val) = (unsafe { at::<CONF_VALUE>(values.cast(), i) }) else { return false };
                // SAFETY: its name.
                let name = unsafe { text(val.name) };
                let (afi, with_safi) = if name_is(name, b"IPv4") {
                    (IANA_AFI_IPV4, false)
                } else if name_is(name, b"IPv6") {
                    (IANA_AFI_IPV6, false)
                } else if name_is(name, b"IPv4-SAFI") {
                    (IANA_AFI_IPV4, true)
                } else if name_is(name, b"IPv6-SAFI") {
                    (IANA_AFI_IPV6, true)
                } else {
                    err::raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_NAME_ERROR, F);
                    err::add_error_data([name]);
                    return false;
                };
                let afi = c_uint::try_from(afi).unwrap_or(0);
                let chars = if afi_len(afi) == 4 { V4 } else { V6 };
                let length = afi_len(afi);
                // SAFETY: its value.
                let value = unsafe { text(val.value) };
                let mut safi_: c_uint = 0;
                let s: Vec<u8> = if with_safi {
                    let Some(v) = value else {
                        err::raise(ERR_LIB_X509V3, X509V3_R_MISSING_VALUE, F);
                        return false;
                    };
                    let (n, used) = strtoul(v, true);
                    safi_ = low32(n);
                    let mut t = v.get(used..).unwrap_or_default();
                    t = t.get(span(t, b" \t")..).unwrap_or_default();
                    let colon = t.first() == Some(&b':');
                    if safi_ > 0xFF || !colon {
                        // SAFETY: the value.
                        unsafe { value_err(X509V3_R_INVALID_SAFI, val, F) };
                        return false;
                    }
                    t = t.get(1..).unwrap_or_default();
                    t.get(span(t, b" \t")..).unwrap_or_default().to_vec()
                } else {
                    // `OPENSSL_strdup(NULL)` fails, as OpenSSL's does.
                    let Some(v) = value else { return false };
                    v.to_vec()
                };
                let safi: *const c_uint = if with_safi { &raw const safi_ } else { ptr::null() };
                if s == b"inherit" {
                    // SAFETY: made above; the SAFI, or NULL.
                    if unsafe { X509v3_addr_add_inherit(addr, afi, safi) } == 0 {
                        // SAFETY: the value.
                        unsafe { value_err(X509V3_R_INVALID_INHERITANCE, val, F) };
                        return false;
                    }
                    continue;
                }
                let i1 = span(&s, chars);
                let mut i2 = i1.saturating_add(span(s.get(i1..).unwrap_or_default(), b" \t"));
                let delim = s.get(i2).copied().unwrap_or(0);
                i2 = i2.saturating_add(1);
                let first = rustyssl_pki::ip::parse(s.get(..i1).unwrap_or_default());
                let Some(min) = first.filter(|a| a.len() == length).and_then(|a| {
                    let mut m = [0u8; RAW];
                    m.get_mut(..length)?.copy_from_slice(&a);
                    Some(m)
                }) else {
                    // SAFETY: the value.
                    unsafe { value_err(X509V3_R_INVALID_IPADDRESS, val, F) };
                    return false;
                };
                match delim {
                    b'/' => {
                        let rest = s.get(i2..).unwrap_or_default();
                        let (n, used) = strtoul(rest, false);
                        let prefixlen = c_int::from_ne_bytes(low32(n).to_ne_bytes());
                        let max_bits = c_int::try_from(length.saturating_mul(8)).unwrap_or(0);
                        if used == 0 || used != rest.len() || prefixlen > max_bits || prefixlen < 0 {
                            // SAFETY: the value.
                            unsafe { value_err(X509V3_R_EXTENSION_VALUE_ERROR, val, F) };
                            return false;
                        }
                        let mut m = min;
                        // SAFETY: made above; the SAFI, or NULL; the address.
                        if unsafe { X509v3_addr_add_prefix(addr, afi, safi, m.as_mut_ptr(), prefixlen) } == 0 {
                            err::raise(ERR_LIB_X509V3, ERR_R_X509V3_LIB, F);
                            return false;
                        }
                    }
                    b'-' => {
                        let j1 = i2.saturating_add(span(s.get(i2..).unwrap_or_default(), b" \t"));
                        let j2 = j1.saturating_add(span(s.get(j1..).unwrap_or_default(), chars));
                        if j1 == j2 || j2 != s.len() {
                            // SAFETY: the value.
                            unsafe { value_err(X509V3_R_EXTENSION_VALUE_ERROR, val, F) };
                            return false;
                        }
                        let second = rustyssl_pki::ip::parse(s.get(j1..).unwrap_or_default());
                        let Some(max) = second.filter(|a| a.len() == length).and_then(|a| {
                            let mut m = [0u8; RAW];
                            m.get_mut(..length)?.copy_from_slice(&a);
                            Some(m)
                        }) else {
                            // SAFETY: the value.
                            unsafe { value_err(X509V3_R_INVALID_IPADDRESS, val, F) };
                            return false;
                        };
                        if cmp_n(&min, &max, length) == Ordering::Greater {
                            // SAFETY: the value.
                            unsafe { value_err(X509V3_R_EXTENSION_VALUE_ERROR, val, F) };
                            return false;
                        }
                        let (mut lo, mut hi) = (min, max);
                        // SAFETY: made above; the SAFI, or NULL; the addresses.
                        if unsafe { X509v3_addr_add_range(addr, afi, safi, lo.as_mut_ptr(), hi.as_mut_ptr()) } == 0 {
                            err::raise(ERR_LIB_X509V3, ERR_R_X509V3_LIB, F);
                            return false;
                        }
                    }
                    0 => {
                        let mut m = min;
                        let bits = c_int::try_from(length.saturating_mul(8)).unwrap_or(0);
                        // SAFETY: made above; the SAFI, or NULL; the address.
                        if unsafe { X509v3_addr_add_prefix(addr, afi, safi, m.as_mut_ptr(), bits) } == 0 {
                            err::raise(ERR_LIB_X509V3, ERR_R_X509V3_LIB, F);
                            return false;
                        }
                    }
                    _ => {
                        // SAFETY: the value.
                        unsafe { value_err(X509V3_R_EXTENSION_VALUE_ERROR, val, F) };
                        return false;
                    }
                }
            }
            // SAFETY: made above.
            (unsafe { X509v3_addr_canonize(addr) } != 0)
        })();
        if ok {
            return addr.cast();
        }
        // SAFETY: made here, with its families.
        unsafe { OPENSSL_sk_pop_free(addr.cast(), Some(free_family)) };
        ptr::null_mut()
    }
}

/// `IPAddressFamily_free` as a stack's free function.
pub(crate) unsafe extern "C" fn free_family(p: *mut c_void) {
    // SAFETY: a family of the stack, which the stack owned.
    unsafe { IPAddressFamily_free(p.cast()) };
}

pub(crate) static ADDR: Method = Method({
    let mut m = method(NID_sbgp_ipAddrBlock, 0);
    m.it = Some(ip_addr_blocks_it);
    m.v2i = Some(addr_v2i);
    m.i2r = Some(addr_i2r);
    m
});

// Path validation (RFC 3779 section 2.3 and 3.3): each certificate's resources within its
// issuer's.

/// A certificate's cached AS identifiers, or NULL (also for NULL).
fn asid_of(x: *const X509) -> *mut ASIdentifiers {
    // SAFETY: a chain's certificate, or NULL.
    unsafe { cache_view(x) }.asid
}

/// A certificate's cached address blocks, or NULL (also for NULL).
fn addr_of(x: *const X509) -> *mut IPAddrBlocks {
    // SAFETY: as above.
    unsafe { cache_view(x) }.addr
}

/// The chain's certificate at `i`.
fn chain_at(chain: *mut stack_st_X509, i: c_int) -> *mut X509 {
    // SAFETY: a live list of certificates, or NULL.
    unsafe { OPENSSL_sk_value(chain.cast(), i) }.cast()
}

/// `validation_err`'s report: with a context, `err` for `x` at depth `i` to its callback (its
/// answer); without one, 0.
///
/// # Safety
/// `ctx` is NULL or a live context.
unsafe fn report(ctx: *mut X509_STORE_CTX, err: c_int, i: c_int, x: *mut X509) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return 0;
    };
    c.error = err;
    c.error_depth = i;
    c.current_cert = x;
    let cb = c.verify_cb;
    // SAFETY: the context's callback, with no reference into the context held.
    cb.map_or(0, |f| unsafe { f(0, ctx) })
}

/// Sets the context's error (if any) to `X509_V_ERR_UNSPECIFIED`: 0.
///
/// # Safety
/// `ctx` is NULL or a live context.
unsafe fn unspecified(ctx: *mut X509_STORE_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    if let Some(c) = unsafe { ctx_of(ctx) } {
        c.error = X509_V_ERR_UNSPECIFIED;
    }
    0
}

/// Whether the arguments are as the path validations need them (`ossl_assert`s): a chain,
/// and a context with a callback or resources.
///
/// # Safety
/// `ctx` is NULL or a live context; `chain` is NULL or a live list.
unsafe fn validation_args_ok(
    ctx: *mut X509_STORE_CTX,
    chain: *mut stack_st_X509,
    ext_given: bool,
) -> bool {
    // SAFETY: the caller's guarantee.
    let n = unsafe { OPENSSL_sk_num(chain.cast()) };
    // SAFETY: as above.
    let ctx_ok = unsafe { ctx_of(ctx) }.map_or(ext_given, |c| c.verify_cb.is_some());
    !chain.is_null() && n > 0 && ctx_ok
}

/// A choice's identifiers if it lists them, and whether it inherits.
fn as_choice_of(c: *mut ASIdentifierChoice) -> Option<(*mut ASIdOrRanges, bool)> {
    // SAFETY: an identifiers' choice, or NULL.
    let c = unsafe { c.as_ref() }?;
    Some(if c.type_ == ASIdentifierChoice_asIdsOrRanges {
        (as_list(c), false)
    } else {
        (ptr::null_mut(), c.type_ == ASIdentifierChoice_inherit)
    })
}

/// `asid_validate_path_internal`: the AS identifiers of `ext` (or the chain's leaf's) within
/// each issuer's up the chain, each failure going to the context's callback (or failing).
///
/// # Safety
/// `ctx` is NULL or a live context; `chain` is NULL or a live list of live certificates;
/// `ext` is NULL or live identifiers.
unsafe fn asid_validate(
    ctx: *mut X509_STORE_CTX,
    chain: *mut stack_st_X509,
    ext: *mut ASIdentifiers,
) -> c_int {
    // SAFETY: the caller's guarantee.
    if !unsafe { validation_args_ok(ctx, chain, !ext.is_null()) } {
        // SAFETY: as above.
        return unsafe { unspecified(ctx) };
    }
    let mut ret = 1;
    let (mut i, mut x, ext) = if ext.is_null() {
        let x = chain_at(chain, 0);
        let ext = asid_of(x);
        if ext.is_null() {
            return ret;
        }
        (0, x, ext)
    } else {
        (-1, ptr::null_mut(), ext)
    };
    macro_rules! verr {
        ($err:expr) => {
            // SAFETY: the caller's context, or NULL.
            ret = unsafe { report(ctx, $err, i, x) };
            if ret == 0 {
                return ret;
            }
        };
    }
    // SAFETY: the identifiers.
    if unsafe { X509v3_asid_is_canonical(ext) } == 0 {
        verr!(X509_V_ERR_INVALID_EXTENSION);
    }
    // SAFETY: as above.
    let e = unsafe { &*ext };
    let (mut child_as, mut inherit_as) = as_choice_of(e.asnum).unwrap_or((ptr::null_mut(), false));
    let (mut child_rdi, mut inherit_rdi) = as_choice_of(e.rdi).unwrap_or((ptr::null_mut(), false));
    // SAFETY: the caller's list.
    let n = unsafe { OPENSSL_sk_num(chain.cast()) };
    i += 1;
    while i < n {
        x = chain_at(chain, i);
        if x.is_null() {
            // SAFETY: as above.
            return unsafe { unspecified(ctx) };
        }
        let xa = asid_of(x);
        // SAFETY: the certificate's identifiers, or NULL.
        let Some(xr) = (unsafe { xa.as_ref() }) else {
            if !child_as.is_null() || !child_rdi.is_null() {
                verr!(X509_V_ERR_UNNESTED_RESOURCE);
            }
            i += 1;
            continue;
        };
        // SAFETY: as above.
        if unsafe { X509v3_asid_is_canonical(xa) } == 0 {
            verr!(X509_V_ERR_INVALID_EXTENSION);
        }
        for (choice, child, inherit) in [
            (xr.asnum, &mut child_as, &mut inherit_as),
            (xr.rdi, &mut child_rdi, &mut inherit_rdi),
        ] {
            let parent = as_choice_of(choice);
            if parent.is_none() && !child.is_null() {
                verr!(X509_V_ERR_UNNESTED_RESOURCE);
                *child = ptr::null_mut();
                *inherit = false;
            }
            // SAFETY: the choice, if any.
            if unsafe { choice.as_ref() }
                .is_some_and(|c| c.type_ == ASIdentifierChoice_asIdsOrRanges)
            {
                let list = parent.map_or(ptr::null_mut(), |(l, _)| l);
                if *inherit || as_contains(list, *child) {
                    *child = list;
                    *inherit = false;
                } else {
                    verr!(X509_V_ERR_UNNESTED_RESOURCE);
                }
            }
        }
        i += 1;
    }
    if x.is_null() {
        // SAFETY: as above.
        return unsafe { unspecified(ctx) };
    }
    // The trust anchor can't inherit.
    // SAFETY: the last certificate's identifiers, or NULL.
    if let Some(xr) = unsafe { asid_of(x).as_ref() } {
        for choice in [xr.asnum, xr.rdi] {
            if as_choice_of(choice).is_some_and(|(_, inherit)| inherit) {
                verr!(X509_V_ERR_UNNESTED_RESOURCE);
            }
        }
    }
    ret
}

ffi_export! {
    /// Validates the AS identifiers down the context's chain (RFC 3779 section 3.3), each
    /// failure going to the callback: 1, or 0 (also, with `X509_V_ERR_UNSPECIFIED`, for no
    /// chain or callback), or the callback's answer.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn X509v3_asid_validate_path(ctx: *mut X509_STORE_CTX) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        let chain = c.chain;
        // SAFETY: the context's chain, or NULL.
        if chain.is_null() || unsafe { OPENSSL_sk_num(chain.cast()) } == 0 || c.verify_cb.is_none() {
            c.error = X509_V_ERR_UNSPECIFIED;
            return 0;
        }
        // SAFETY: the context and its chain.
        unsafe { asid_validate(ctx, chain, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Whether the identifiers `ext` (inheriting only if `allow_inheritance`) are within the
    /// chain's (the issuer first): 1 (also for NULL `ext`), or 0.
    ///
    /// # Safety
    /// `chain` is NULL or a live list of live certificates; `ext` is NULL or live identifiers.
    pub unsafe extern "C" fn X509v3_asid_validate_resource_set(chain: *mut stack_st_X509, ext: *mut ASIdentifiers, allow_inheritance: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        if ext.is_null() {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        if chain.is_null() || unsafe { OPENSSL_sk_num(chain.cast()) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        if allow_inheritance == 0 && unsafe { X509v3_asid_inherits(ext) } != 0 {
            return 0;
        }
        // SAFETY: as above.
        unsafe { asid_validate(ptr::null_mut(), chain, ext) }
    }
}

/// A family's choice's type, or `None` for no choice.
fn choice_type(f: &IPAddressFamily) -> Option<c_int> {
    // SAFETY: the family's choice, or NULL.
    unsafe { f.ipAddressChoice.as_ref() }.map(|c| c.type_)
}

/// A family's addresses (whatever its choice's type), or NULL.
fn family_list(f: &IPAddressFamily) -> *mut IPAddressOrRanges {
    // SAFETY: as above.
    unsafe { f.ipAddressChoice.as_ref() }.map_or(ptr::null_mut(), ip_list)
}

/// The family at `j` of a list.
fn family_at<'a>(sk: *mut c_void, j: c_int) -> Option<&'a IPAddressFamily> {
    // SAFETY: a live list of families, or NULL.
    let f = unsafe { OPENSSL_sk_value(sk.cast(), j) }.cast::<IPAddressFamily>();
    // SAFETY: as above.
    unsafe { f.as_ref() }
}

/// `addr_validate_path_internal`: the address blocks of `ext` (or the chain's leaf's) within
/// each issuer's up the chain, family by family, each failure going to the context's
/// callback (or failing). Sorts each certificate's families, as OpenSSL does.
///
/// # Safety
/// As for [`asid_validate`], `ext` being NULL or a live list of families.
unsafe fn addr_validate(
    ctx: *mut X509_STORE_CTX,
    chain: *mut stack_st_X509,
    ext: *mut IPAddrBlocks,
) -> c_int {
    // SAFETY: the caller's guarantee.
    if !unsafe { validation_args_ok(ctx, chain, !ext.is_null()) } {
        // SAFETY: as above.
        return unsafe { unspecified(ctx) };
    }
    let (mut i, mut x, ext) = if ext.is_null() {
        let x = chain_at(chain, 0);
        let ext = addr_of(x);
        if ext.is_null() {
            return 1;
        }
        (0, x, ext)
    } else {
        (-1, ptr::null_mut(), ext)
    };
    let mut child: *mut c_void = ptr::null_mut();
    // SAFETY: the context, or NULL; the chain; the families.
    let ret = 'done: {
        macro_rules! verr {
            ($err:expr) => {
                // SAFETY: the caller's context, or NULL.
                if unsafe { report(ctx, $err, i, x) } == 0 {
                    break 'done 0;
                }
            };
        }
        // SAFETY: the families.
        if unsafe { X509v3_addr_is_canonical(ext) } == 0 {
            verr!(X509_V_ERR_INVALID_EXTENSION);
        }
        // SAFETY: as above; a comparison of families.
        unsafe { OPENSSL_sk_set_cmp_func(ext.cast(), Some(family_cmp)) };
        // SAFETY: as above.
        child = unsafe { OPENSSL_sk_dup(ext.cast()) }.cast();
        if child.is_null() {
            err::raise(
                ERR_LIB_X509V3,
                ERR_R_CRYPTO_LIB,
                "addr_validate_path_internal",
            );
            // SAFETY: the caller's context, or NULL.
            if let Some(c) = unsafe { ctx_of(ctx) } {
                c.error = X509_V_ERR_OUT_OF_MEM;
            }
            break 'done 0;
        }
        // SAFETY: the copy.
        unsafe { OPENSSL_sk_sort(child.cast()) };
        // SAFETY: the caller's list.
        let n = unsafe { OPENSSL_sk_num(chain.cast()) };
        // SAFETY: the copy.
        let nchild = || unsafe { OPENSSL_sk_num(child.cast()) };
        i += 1;
        while i < n {
            x = chain_at(chain, i);
            if x.is_null() {
                // SAFETY: as above.
                break 'done unsafe { unspecified(ctx) };
            }
            let xa = addr_of(x);
            // SAFETY: the certificate's families, or NULL.
            if unsafe { X509v3_addr_is_canonical(xa) } == 0 {
                verr!(X509_V_ERR_INVALID_EXTENSION);
            }
            if xa.is_null() {
                for j in 0..nchild() {
                    let Some(fc) = family_at(child, j) else {
                        break 'done 0;
                    };
                    if !family_len_ok(fc) {
                        break 'done 0;
                    }
                    if choice_type(fc) != Some(IPAddressChoice_inherit) {
                        verr!(X509_V_ERR_UNNESTED_RESOURCE);
                        break;
                    }
                }
                i += 1;
                continue;
            }
            // SAFETY: as above; a comparison of families.
            unsafe { OPENSSL_sk_set_cmp_func(xa.cast(), Some(family_cmp)) };
            // SAFETY: as above.
            unsafe { OPENSSL_sk_sort(xa.cast()) };
            for j in 0..nchild() {
                let Some(fc) = family_at(child, j) else {
                    break 'done 0;
                };
                // SAFETY: the certificate's families; a family to find.
                let k = unsafe { OPENSSL_sk_find(xa.cast(), ptr::from_ref(fc).cast()) };
                let Some(fp) = family_at(xa.cast(), k) else {
                    if choice_type(fc) == Some(IPAddressChoice_addressesOrRanges) {
                        verr!(X509_V_ERR_UNNESTED_RESOURCE);
                        break;
                    }
                    continue;
                };
                if !family_len_ok(fc) || !family_len_ok(fp) {
                    break 'done 0;
                }
                if choice_type(fp) == Some(IPAddressChoice_addressesOrRanges) {
                    let fc_ptr = ptr::from_ref(fc);
                    if choice_type(fc) == Some(IPAddressChoice_inherit)
                        || ip_contains(family_list(fp), family_list(fc), family_addr_len(fc_ptr))
                    {
                        // SAFETY: the copy; an index within it; the issuer's family.
                        unsafe { OPENSSL_sk_set(child.cast(), j, ptr::from_ref(fp).cast()) };
                    } else {
                        verr!(X509_V_ERR_UNNESTED_RESOURCE);
                    }
                }
            }
            i += 1;
        }
        // The trust anchor can't inherit.
        let xa = addr_of(x);
        if !xa.is_null() {
            // SAFETY: the certificate's families.
            for j in 0..unsafe { OPENSSL_sk_num(xa.cast()) } {
                let Some(fp) = family_at(xa.cast(), j) else {
                    break 'done 0;
                };
                if !family_len_ok(fp) {
                    break 'done 0;
                }
                if choice_type(fp) == Some(IPAddressChoice_inherit)
                    // SAFETY: the copy; a family to find.
                    && unsafe { OPENSSL_sk_find(child.cast(), ptr::from_ref(fp).cast()) } >= 0
                {
                    verr!(X509_V_ERR_UNNESTED_RESOURCE);
                }
            }
        }
        1
    };
    // SAFETY: the copy, or NULL.
    unsafe { OPENSSL_sk_free(child.cast()) };
    ret
}

ffi_export! {
    /// Validates the address blocks down the context's chain (RFC 3779 section 2.3), each
    /// failure going to the callback: 1, or 0 (also, with `X509_V_ERR_UNSPECIFIED`, for no
    /// chain or callback).
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn X509v3_addr_validate_path(ctx: *mut X509_STORE_CTX) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        let chain = c.chain;
        // SAFETY: the context's chain, or NULL.
        if chain.is_null() || unsafe { OPENSSL_sk_num(chain.cast()) } == 0 || c.verify_cb.is_none() {
            c.error = X509_V_ERR_UNSPECIFIED;
            return 0;
        }
        // SAFETY: the context and its chain.
        unsafe { addr_validate(ctx, chain, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Whether the address blocks `ext` (inheriting only if `allow_inheritance`) are within
    /// the chain's (the issuer first): 1 (also for NULL `ext`), or 0.
    ///
    /// # Safety
    /// `chain` is NULL or a live list of live certificates; `ext` is NULL or a live list of
    /// families.
    pub unsafe extern "C" fn X509v3_addr_validate_resource_set(chain: *mut stack_st_X509, ext: *mut IPAddrBlocks, allow_inheritance: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        if ext.is_null() {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        if chain.is_null() || unsafe { OPENSSL_sk_num(chain.cast()) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        if allow_inheritance == 0 && unsafe { X509v3_addr_inherits(ext) } != 0 {
            return 0;
        }
        // SAFETY: as above.
        unsafe { addr_validate(ptr::null_mut(), chain, ext) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strtoul_follows_c() {
        assert_eq!(strtoul(b"12:x", true), (12, 2));
        assert_eq!(strtoul(b"0x1f:", true), (31, 4));
        assert_eq!(strtoul(b"010", true), (8, 3));
        assert_eq!(strtoul(b"0x", true), (0, 1));
        assert_eq!(strtoul(b"  +7", false), (7, 4));
        assert_eq!(strtoul(b"-1", false), (u64::MAX, 2));
        assert_eq!(strtoul(b":", true), (0, 0));
        assert_eq!(strtoul(b"99999999999999999999999", false).0, u64::MAX);
    }

    /// docs/DEVIATIONS.md: families without their parts and ranges without bounds, which
    /// OpenSSL reads through, answer 0.
    #[test]
    fn missing_parts_fail() {
        // SAFETY: no preconditions.
        let addr = unsafe { OPENSSL_sk_new_null() }.cast::<IPAddrBlocks>();
        // SAFETY: as above.
        let f = unsafe { IPAddressFamily_new() };
        // SAFETY: the new family.
        let fr = unsafe { &mut *f };
        // SAFETY: its parts, freed and taken away.
        unsafe { IPAddressChoice_free(fr.ipAddressChoice) };
        // SAFETY: as above.
        unsafe { crate::asn1::string::ASN1_OCTET_STRING_free(fr.addressFamily) };
        fr.ipAddressChoice = ptr::null_mut();
        fr.addressFamily = ptr::null_mut();
        // SAFETY: the stack; the family, which it takes.
        assert_eq!(unsafe { OPENSSL_sk_push(addr.cast(), f.cast()) }, 1);
        // SAFETY: the family without its parts.
        assert_eq!(unsafe { X509v3_addr_get_afi(f) }, 0);
        // SAFETY: the stack holding it.
        assert_eq!(unsafe { X509v3_addr_inherits(addr) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509v3_addr_is_canonical(addr) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509v3_addr_canonize(addr) }, 0);
        // SAFETY: no preconditions.
        let empty = unsafe { OPENSSL_sk_new_null() }.cast::<IPAddrBlocks>();
        // SAFETY: the stack holding the family; an empty one.
        assert_eq!(unsafe { X509v3_addr_subset(addr, empty) }, 0);
        // SAFETY: made above.
        unsafe { crate::stack::OPENSSL_sk_free(empty.cast()) };
        // SAFETY: no preconditions.
        let aor = unsafe { IPAddressOrRange_new() };
        // SAFETY: the new range, without bounds.
        unsafe { (*aor).type_ = IPAddressOrRange_addressRange };
        let (mut min, mut max) = ([0u8; RAW], [0u8; RAW]);
        // SAFETY: as above; buffers of 16 octets.
        let n = unsafe { X509v3_addr_get_range(aor, 1, min.as_mut_ptr(), max.as_mut_ptr(), 16) };
        assert_eq!(n, 0);
        // SAFETY: made above.
        unsafe { IPAddressOrRange_free(aor) };
        // SAFETY: as above, with its family.
        unsafe { OPENSSL_sk_pop_free(addr.cast(), Some(free_family)) };
        crate::err::take_all();
    }

    #[test]
    fn prefixes_of_ranges() {
        let mut lo = [0u8; RAW];
        let mut hi = [0u8; RAW];
        lo[..4].copy_from_slice(&[10, 0, 0, 0]);
        hi[..4].copy_from_slice(&[10, 255, 255, 255]);
        assert_eq!(range_prefix(&lo, &hi, 4), Some(8));
        hi[..4].copy_from_slice(&[10, 0, 0, 0]);
        assert_eq!(range_prefix(&lo, &hi, 4), Some(32));
        hi[..4].copy_from_slice(&[10, 0, 0, 5]);
        assert_eq!(range_prefix(&lo, &hi, 4), None);
        hi[..4].copy_from_slice(&[10, 0, 0, 7]);
        assert_eq!(range_prefix(&lo, &hi, 4), Some(29));
        let all = [0xFFu8; RAW];
        assert_eq!(range_prefix(&[0; RAW], &all, 4), Some(0));
    }

    /// docs/DEVIATIONS.md: a NULL certificate in the chain, which OpenSSL's address
    /// validation reads through, fails the validation.
    #[test]
    fn null_certificates_in_chains_fail() {
        // SAFETY: new lists, freed below.
        let chain = unsafe { OPENSSL_sk_new_null() };
        // SAFETY: as above.
        let ext = unsafe { OPENSSL_sk_new(Some(family_cmp)) };
        // SAFETY: the list; NULL where OpenSSL dereferences it.
        assert_eq!(unsafe { OPENSSL_sk_push(chain, ptr::null()) }, 1);
        // SAFETY: the lists.
        let r = unsafe { X509v3_addr_validate_resource_set(chain.cast(), ext.cast(), 1) };
        assert_eq!(r, 0);
        // SAFETY: no preconditions; freed below.
        let asid = unsafe { ASIdentifiers_new() };
        // SAFETY: as above.
        let r = unsafe { X509v3_asid_validate_resource_set(chain.cast(), asid, 1) };
        assert_eq!(r, 0);
        // SAFETY: made above.
        unsafe { ASIdentifiers_free(asid) };
        // SAFETY: made above.
        unsafe { OPENSSL_sk_free(chain) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_free(ext) };
    }
}
