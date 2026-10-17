//! `ASN1_generate_nconf` and `ASN1_generate_v3` (`asn1_gen.c`): a value from OpenSSL's string
//! mini-language, `[modifier,...]type[:value]`. The types are the universal ones (with their
//! short names) and SEQUENCE and SET, whose elements are a configuration section's values;
//! the modifiers are implicit (`IMP`) and explicit (`EXP`) tagging, wrapping in a SEQUENCE,
//! SET, OCTET STRING, or BIT STRING, and the value's `FORMAT` (ASCII, UTF8, HEX, BITLIST).
//!
//! As OpenSSL's:
//! - The list stops at the type, so its value runs to the end of the string, commas and all.
//! - Tag numbers are read as `strtoul` reads them and truncated to an `int`.
//! - At most 20 explicit tags and wrappers, and SEQUENCE and SET nested 50 deep.

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_R_DEPTH_EXCEEDED, ASN1_R_ILLEGAL_BITSTRING_FORMAT, ASN1_R_ILLEGAL_BOOLEAN,
    ASN1_R_ILLEGAL_FORMAT, ASN1_R_ILLEGAL_HEX, ASN1_R_ILLEGAL_IMPLICIT_TAG, ASN1_R_ILLEGAL_INTEGER,
    ASN1_R_ILLEGAL_NESTED_TAGGING, ASN1_R_ILLEGAL_NULL_VALUE, ASN1_R_ILLEGAL_OBJECT,
    ASN1_R_ILLEGAL_TIME_VALUE, ASN1_R_INTEGER_NOT_ASCII_FORMAT, ASN1_R_INVALID_MODIFIER,
    ASN1_R_INVALID_NUMBER, ASN1_R_LIST_ERROR, ASN1_R_MISSING_VALUE, ASN1_R_NOT_ASCII_FORMAT,
    ASN1_R_OBJECT_NOT_ASCII_FORMAT, ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG,
    ASN1_R_TIME_NOT_ASCII_FORMAT, ASN1_R_UNKNOWN_FORMAT, ASN1_R_UNKNOWN_TAG,
    ASN1_R_UNSUPPORTED_TYPE, ASN1_STRING, ASN1_STRING_FLAG_BITS_LEFT, ASN1_TYPE, CONF, CONF_VALUE,
    ERR_LIB_ASN1, ERR_R_ASN1_LIB, MBSTRING_ASC, MBSTRING_UTF8, V_ASN1_APPLICATION,
    V_ASN1_BIT_STRING, V_ASN1_BMPSTRING, V_ASN1_BOOLEAN, V_ASN1_CONSTRUCTED,
    V_ASN1_CONTEXT_SPECIFIC, V_ASN1_ENUMERATED, V_ASN1_GENERALIZEDTIME, V_ASN1_GENERALSTRING,
    V_ASN1_IA5STRING, V_ASN1_INTEGER, V_ASN1_NULL, V_ASN1_NUMERICSTRING, V_ASN1_OBJECT,
    V_ASN1_OCTET_STRING, V_ASN1_PRINTABLESTRING, V_ASN1_PRIVATE, V_ASN1_SEQUENCE, V_ASN1_SET,
    V_ASN1_T61STRING, V_ASN1_UNIVERSAL, V_ASN1_UNIVERSALSTRING, V_ASN1_UTCTIME, V_ASN1_UTF8STRING,
    V_ASN1_VISIBLESTRING, X509V3_CTX,
};
use rustyssl_asn1::gen_tags::{
    GEN_FLAG, GEN_FLAG_BITWRAP, GEN_FLAG_EXP, GEN_FLAG_FORMAT, GEN_FLAG_IMP, GEN_FLAG_OCTWRAP,
    GEN_FLAG_SEQWRAP, GEN_FLAG_SETWRAP, str2tag,
};

use crate::asn1::bit_string::ASN1_BIT_STRING_set_bit;
use crate::asn1::string::{ASN1_STRING_new, ASN1_STRING_set, ASN1_STRING_type_new};
use crate::asn1::text::{ASN1_mbstring_copy, ASN1_tag2bit};
use crate::asn1::time::ASN1_TIME_check;
use crate::asn1::tpl::items::{
    ASN1_TYPE_free, ASN1_TYPE_new, d2i_ASN1_TYPE, i2d_ASN1_SEQUENCE_ANY, i2d_ASN1_SET_ANY,
    i2d_ASN1_TYPE,
};
use crate::asn1::{ASN1_get_object, ASN1_object_size, ASN1_put_object};
use crate::conf::CONF_parse_list;
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::objects::OBJ_txt2obj;
use crate::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::string::OPENSSL_hexstr2buf;
use crate::x509v3::ctx::{X509V3_get_section, X509V3_section_free, X509V3_set_nconf};
use crate::x509v3::{X509V3_get_value_bool, s2i_ASN1_INTEGER};

/// The most explicit tags and wrappers (`ASN1_FLAG_EXP_MAX`).
const EXP_MAX: usize = 20;
/// How deep SEQUENCE and SET nest (`ASN1_GEN_SEQ_MAX_DEPTH`).
const SEQ_MAX_DEPTH: c_int = 50;

// The value's formats (`ASN1_GEN_FORMAT_*`).
const FORMAT_ASCII: c_int = 1;
const FORMAT_UTF8: c_int = 2;
const FORMAT_HEX: c_int = 3;
const FORMAT_BITLIST: c_int = 4;

/// An explicit tag or wrapper (`tag_exp_type`).
#[derive(Clone, Copy, Default)]
struct Exp {
    tag: c_int,
    class: c_int,
    constructed: c_int,
    pad: c_int,
    len: c_long,
}

/// What the modifiers and the type say (`tag_exp_arg`).
struct Arg {
    imp_tag: c_int,
    imp_class: c_int,
    utype: c_int,
    format: c_int,
    str_: *const c_char,
    exp: Vec<Exp>,
}

/// `strtoul(s, &end, 10)`: the value (wrapped as C's is) and how many octets it read (0 if no
/// digits).
fn strtoul10(s: &[u8]) -> (u64, usize) {
    let mut i = s
        .iter()
        .take_while(|c| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
        .count();
    let neg = match s.get(i) {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };
    let start = i;
    let mut v: u64 = 0;
    let mut overflow = false;
    while let Some(&c) = s.get(i).filter(|c| c.is_ascii_digit()) {
        match v
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(c - b'0')))
        {
            Some(n) => v = n,
            None => overflow = true,
        }
        i += 1;
    }
    if i == start {
        return (0, 0);
    }
    let v = if overflow {
        u64::MAX
    } else if neg {
        v.wrapping_neg()
    } else {
        v
    };
    (v, i)
}

/// A NUL-terminated string from `p` (empty for NULL).
///
/// # Safety
/// `p` is NULL or a C string.
unsafe fn cstr<'a>(p: *const c_char) -> &'a [u8] {
    if p.is_null() {
        return &[];
    }
    // SAFETY: the caller's guarantee.
    unsafe { CStr::from_ptr(p) }.to_bytes()
}

/// C's `(int)` of a `long`.
fn as_int(v: u64) -> c_int {
    u32::try_from(v & u64::from(u32::MAX))
        .unwrap_or(0)
        .cast_signed()
}

/// `parse_tagging`: a tag number and its class (`U`, `A`, `P`, `C`; context-specific without
/// one) from the `vlen` octets at `vstart`.
///
/// # Safety
/// `vstart` is NULL or a C string.
unsafe fn parse_tagging(vstart: *const c_char, vlen: usize) -> Option<(c_int, c_int)> {
    if vstart.is_null() {
        return None;
    }
    // SAFETY: the caller's guarantee.
    let s = unsafe { cstr(vstart) };
    let (v, used) = strtoul10(s);
    if s.get(used).is_some_and(|&c| c != 0) && used > vlen {
        return None;
    }
    if v.cast_signed() < 0 {
        err::raise(ERR_LIB_ASN1, ASN1_R_INVALID_NUMBER, "parse_tagging");
        return None;
    }
    let tag = as_int(v);
    let rest = vlen.saturating_sub(used);
    if rest == 0 {
        return Some((tag, V_ASN1_CONTEXT_SPECIFIC));
    }
    let c = s.get(used).copied().unwrap_or(0);
    let class = match c {
        b'U' => V_ASN1_UNIVERSAL,
        b'A' => V_ASN1_APPLICATION,
        b'P' => V_ASN1_PRIVATE,
        b'C' => V_ASN1_CONTEXT_SPECIFIC,
        _ => {
            let text = format!("Char={}", char::from(c));
            err::raise_with_text(
                ERR_LIB_ASN1,
                ASN1_R_INVALID_MODIFIER,
                "parse_tagging",
                &text,
            );
            return None;
        }
    };
    Some((tag, class))
}

/// `append_exp`: an explicit tag (or, after an implicit one, that tag) at the end of the list.
fn append_exp(
    arg: &mut Arg,
    tag: c_int,
    class: c_int,
    constructed: c_int,
    pad: c_int,
    imp_ok: bool,
) -> bool {
    if arg.imp_tag != -1 && !imp_ok {
        err::raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_IMPLICIT_TAG, "append_exp");
        return false;
    }
    if arg.exp.len() == EXP_MAX {
        err::raise(ERR_LIB_ASN1, ASN1_R_DEPTH_EXCEEDED, "append_exp");
        return false;
    }
    let (tag, class) = if arg.imp_tag == -1 {
        (tag, class)
    } else {
        let t = (arg.imp_tag, arg.imp_class);
        arg.imp_tag = -1;
        arg.imp_class = -1;
        t
    };
    arg.exp.push(Exp {
        tag,
        class,
        constructed,
        pad,
        len: 0,
    });
    true
}

ffi_callback! {
    /// `asn1_cb`: one element of the list: a modifier (1, to go on), the type (0, to stop),
    /// or an error (-1).
    ///
    /// # Safety
    /// `elem` is NULL or `len` octets of a C string; `bitstr` is an [`Arg`].
    pub(crate) unsafe extern "C" fn asn1_cb(elem: *const c_char, len: c_int, bitstr: *mut c_void) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let Some(arg) = (unsafe { bitstr.cast::<Arg>().as_mut() }) else { return -1 };
        if elem.is_null() {
            return -1;
        }
        // SAFETY: as above.
        let all = unsafe { cstr(elem) };
        let len = usize::try_from(len).unwrap_or(0).min(all.len());
        let item = all.get(..len).unwrap_or_default();
        let (name_len, vstart, vlen) = match item.iter().position(|&c| c == b':') {
            // SAFETY: within the element.
            Some(i) => (i, unsafe { elem.add(i + 1) }, len - i - 1),
            None => (len, ptr::null(), 0),
        };
        let utype = str2tag(item.get(..name_len).unwrap_or_default());
        if utype == -1 {
            let mut text = b"tag=".to_vec();
            text.extend_from_slice(all);
            err::raise_with_bytes(ERR_LIB_ASN1, ASN1_R_UNKNOWN_TAG, "asn1_cb", &text);
            return -1;
        }
        if utype & GEN_FLAG == 0 {
            arg.utype = utype;
            arg.str_ = vstart;
            if vstart.is_null() && all.get(len).is_some_and(|&c| c != 0) {
                err::raise(ERR_LIB_ASN1, ASN1_R_MISSING_VALUE, "asn1_cb");
                return -1;
            }
            return 0;
        }
        let ok = match utype {
            GEN_FLAG_IMP => {
                if arg.imp_tag != -1 {
                    err::raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_NESTED_TAGGING, "asn1_cb");
                    return -1;
                }
                // SAFETY: the value, within the caller's string.
                match unsafe { parse_tagging(vstart, vlen) } {
                    Some((t, c)) => {
                        arg.imp_tag = t;
                        arg.imp_class = c;
                        true
                    }
                    None => false,
                }
            }
            GEN_FLAG_EXP => {
                // SAFETY: as above.
                unsafe { parse_tagging(vstart, vlen) }.is_some_and(|(t, c)| append_exp(arg, t, c, 1, 0, false))
            }
            GEN_FLAG_SEQWRAP => append_exp(arg, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL, 1, 0, true),
            GEN_FLAG_SETWRAP => append_exp(arg, V_ASN1_SET, V_ASN1_UNIVERSAL, 1, 0, true),
            GEN_FLAG_BITWRAP => append_exp(arg, V_ASN1_BIT_STRING, V_ASN1_UNIVERSAL, 0, 1, true),
            GEN_FLAG_OCTWRAP => append_exp(arg, V_ASN1_OCTET_STRING, V_ASN1_UNIVERSAL, 0, 0, true),
            GEN_FLAG_FORMAT => {
                // SAFETY: as above.
                let v = unsafe { cstr(vstart) };
                let f = if vstart.is_null() {
                    None
                } else if v.starts_with(b"ASCII") {
                    Some(FORMAT_ASCII)
                } else if v.starts_with(b"UTF8") {
                    Some(FORMAT_UTF8)
                } else if v.starts_with(b"HEX") {
                    Some(FORMAT_HEX)
                } else if v.starts_with(b"BITLIST") {
                    Some(FORMAT_BITLIST)
                } else {
                    None
                };
                match f {
                    Some(f) => {
                        arg.format = f;
                        true
                    }
                    None => {
                        err::raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_FORMAT, "asn1_cb");
                        false
                    }
                }
            }
            _ => true,
        };
        if ok { 1 } else { -1 }
    }
}

ffi_callback! {
    /// `bitstr_cb`: sets the bit numbered by the element: 1, or 0.
    ///
    /// # Safety
    /// `elem` is NULL or `len` octets of a C string; `bitstr` is a BIT STRING.
    pub(crate) unsafe extern "C" fn bitstr_cb(elem: *const c_char, len: c_int, bitstr: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if elem.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let s = unsafe { cstr(elem) };
        let (v, used) = strtoul10(s);
        let len = usize::try_from(len).unwrap_or(0);
        if s.get(used).is_some_and(|&c| c != 0) && used != len {
            return 0;
        }
        if v.cast_signed() < 0 {
            err::raise(ERR_LIB_ASN1, ASN1_R_INVALID_NUMBER, "bitstr_cb");
            return 0;
        }
        // SAFETY: the caller's BIT STRING.
        if unsafe { ASN1_BIT_STRING_set_bit(bitstr.cast(), as_int(v), 1) } == 0 {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, "bitstr_cb");
            return 0;
        }
        1
    }
}

/// `asn1_str2type`: a value of `utype` from `str` in `format`, or NULL (with an error and,
/// for a bad value, `string=` and it as the error's data).
///
/// # Safety
/// `str_` is NULL or a C string.
unsafe fn str2type(str_: *const c_char, format: c_int, utype: c_int) -> *mut ASN1_TYPE {
    const F: &str = "asn1_str2type";
    // SAFETY: no preconditions.
    let atmp = unsafe { ASN1_TYPE_new() };
    // SAFETY: new, or NULL.
    let Some(a) = (unsafe { atmp.as_mut() }) else {
        err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
        return ptr::null_mut();
    };
    let str_ = if str_.is_null() { c"".as_ptr() } else { str_ };
    // SAFETY: a C string.
    let s = unsafe { cstr(str_) };
    let raise = |reason| err::raise(ERR_LIB_ASN1, reason, F);
    // `Err(true)` for a bad value (`bad_str`), `Err(false)` for a bad form.
    let r: Result<(), bool> = 'r: {
        match utype {
            V_ASN1_NULL => {
                if !s.is_empty() {
                    raise(ASN1_R_ILLEGAL_NULL_VALUE);
                    break 'r Err(false);
                }
            }
            V_ASN1_BOOLEAN => {
                if format != FORMAT_ASCII {
                    raise(ASN1_R_NOT_ASCII_FORMAT);
                    break 'r Err(false);
                }
                let v = CONF_VALUE {
                    section: ptr::null_mut(),
                    name: ptr::null_mut(),
                    value: str_.cast_mut(),
                };
                let mut b = 0;
                // SAFETY: a value; a local.
                if unsafe { X509V3_get_value_bool(&raw const v, &raw mut b) } == 0 {
                    raise(ASN1_R_ILLEGAL_BOOLEAN);
                    break 'r Err(true);
                }
                a.value.boolean = b;
            }
            V_ASN1_INTEGER | V_ASN1_ENUMERATED => {
                if format != FORMAT_ASCII {
                    raise(ASN1_R_INTEGER_NOT_ASCII_FORMAT);
                    break 'r Err(false);
                }
                // SAFETY: no method; a C string.
                let i = unsafe { s2i_ASN1_INTEGER(ptr::null_mut(), str_) };
                if i.is_null() {
                    raise(ASN1_R_ILLEGAL_INTEGER);
                    break 'r Err(true);
                }
                a.value.integer = i;
            }
            V_ASN1_OBJECT => {
                if format != FORMAT_ASCII {
                    raise(ASN1_R_OBJECT_NOT_ASCII_FORMAT);
                    break 'r Err(false);
                }
                // SAFETY: as above.
                let o = unsafe { OBJ_txt2obj(str_, 0) };
                if o.is_null() {
                    raise(ASN1_R_ILLEGAL_OBJECT);
                    break 'r Err(true);
                }
                a.value.object = o;
            }
            V_ASN1_UTCTIME | V_ASN1_GENERALIZEDTIME => {
                if format != FORMAT_ASCII {
                    raise(ASN1_R_TIME_NOT_ASCII_FORMAT);
                    break 'r Err(false);
                }
                // SAFETY: no preconditions.
                let t = unsafe { ASN1_STRING_new() };
                a.value.asn1_string = t;
                // SAFETY: the new string, or NULL; the value.
                if t.is_null() || unsafe { ASN1_STRING_set(t, str_.cast(), -1) } == 0 {
                    raise(ERR_R_ASN1_LIB);
                    break 'r Err(true);
                }
                // SAFETY: as above.
                unsafe { (*t).type_ = utype };
                // SAFETY: as above.
                if unsafe { ASN1_TIME_check(t) } == 0 {
                    raise(ASN1_R_ILLEGAL_TIME_VALUE);
                    break 'r Err(true);
                }
            }
            V_ASN1_BMPSTRING
            | V_ASN1_PRINTABLESTRING
            | V_ASN1_IA5STRING
            | V_ASN1_T61STRING
            | V_ASN1_UTF8STRING
            | V_ASN1_VISIBLESTRING
            | V_ASN1_UNIVERSALSTRING
            | V_ASN1_GENERALSTRING
            | V_ASN1_NUMERICSTRING => {
                let inform = match format {
                    FORMAT_ASCII => MBSTRING_ASC,
                    FORMAT_UTF8 => MBSTRING_UTF8,
                    _ => {
                        raise(ASN1_R_ILLEGAL_FORMAT);
                        break 'r Err(false);
                    }
                };
                // SAFETY: a type.
                let mask = unsafe { ASN1_tag2bit(utype) };
                // SAFETY: the value's slot; the value.
                if unsafe {
                    ASN1_mbstring_copy(&raw mut a.value.asn1_string, str_.cast(), -1, inform, mask)
                } <= 0
                {
                    raise(ERR_R_ASN1_LIB);
                    break 'r Err(true);
                }
            }
            V_ASN1_BIT_STRING | V_ASN1_OCTET_STRING => {
                // SAFETY: no preconditions.
                let t = unsafe { ASN1_STRING_new() };
                a.value.asn1_string = t;
                // SAFETY: the new string, or NULL.
                let Some(ts) = (unsafe { t.as_mut() }) else {
                    raise(ERR_R_ASN1_LIB);
                    break 'r Err(false);
                };
                let mut bits_left_zero = true;
                if format == FORMAT_HEX {
                    let mut n: c_long = 0;
                    // SAFETY: the value; a local.
                    let d = unsafe { OPENSSL_hexstr2buf(str_, &raw mut n) };
                    if d.is_null() {
                        raise(ASN1_R_ILLEGAL_HEX);
                        break 'r Err(true);
                    }
                    ts.data = d;
                    ts.length = c_int::try_from(n).unwrap_or(0);
                    ts.type_ = utype;
                } else if format == FORMAT_ASCII {
                    // SAFETY: as above.
                    if unsafe { ASN1_STRING_set(t, str_.cast(), -1) } == 0 {
                        raise(ERR_R_ASN1_LIB);
                        break 'r Err(true);
                    }
                } else if format == FORMAT_BITLIST && utype == V_ASN1_BIT_STRING {
                    // SAFETY: the value; the callback and its BIT STRING.
                    if unsafe {
                        CONF_parse_list(str_, c_int::from(b','), 1, Some(bitstr_cb), t.cast())
                    } == 0
                    {
                        raise(ASN1_R_LIST_ERROR);
                        break 'r Err(true);
                    }
                    bits_left_zero = false;
                } else {
                    raise(ASN1_R_ILLEGAL_BITSTRING_FORMAT);
                    break 'r Err(false);
                }
                if utype == V_ASN1_BIT_STRING && bits_left_zero {
                    // SAFETY: as above.
                    let ts = unsafe { &mut *t };
                    ts.flags &= !0x07;
                    ts.flags |= c_long::from(ASN1_STRING_FLAG_BITS_LEFT);
                }
            }
            _ => {
                raise(ASN1_R_UNSUPPORTED_TYPE);
                break 'r Err(true);
            }
        }
        Ok(())
    };
    match r {
        Ok(()) => {
            a.type_ = utype;
            atmp
        }
        Err(bad_str) => {
            if bad_str {
                err::add_error_data([Some(&b"string="[..]), Some(s)]);
            }
            // SAFETY: made above (with what was set; its type unset frees by the type's
            // pointer, as OpenSSL's does).
            unsafe { free_partial(atmp, utype) };
            ptr::null_mut()
        }
    }
}

/// Frees a value `str2type` gave up on: OpenSSL's `ASN1_TYPE_free` of a type whose `type` is
/// still 0, which frees nothing of its value but the object; here the value's string or object
/// is freed too.
///
/// # Safety
/// `a` is a type from `ASN1_TYPE_new` whose value (if any) is of `utype`.
unsafe fn free_partial(a: *mut ASN1_TYPE, utype: c_int) {
    // SAFETY: the caller's guarantee.
    if let Some(t) = unsafe { a.as_mut() } {
        // The value is set only for a pointer type; BOOLEAN and NULL leave none.
        if utype != V_ASN1_BOOLEAN && utype != V_ASN1_NULL {
            // SAFETY: as above.
            if unsafe { !t.value.ptr.is_null() } {
                t.type_ = utype;
            }
        }
    }
    // SAFETY: as above.
    unsafe { ASN1_TYPE_free(a) };
}

/// `ASN1_STRING_free` as a stack's free function of `ASN1_TYPE`s.
unsafe extern "C" fn type_free(p: *mut c_void) {
    // SAFETY: a type of the stack, which the stack owned.
    unsafe { ASN1_TYPE_free(p.cast()) };
}

/// `asn1_multi`: a SEQUENCE or SET of the values of the configuration's `section` (none
/// without one).
///
/// # Safety
/// `section` is NULL or a C string; `cnf` is a live context.
unsafe fn multi(
    utype: c_int,
    section: *const c_char,
    cnf: *mut X509V3_CTX,
    depth: c_int,
    perr: &mut c_int,
) -> *mut ASN1_TYPE {
    // SAFETY: no preconditions.
    let sk = unsafe { OPENSSL_sk_new_null() };
    if sk.is_null() {
        return ptr::null_mut();
    }
    let mut sect = ptr::null_mut();
    let mut der: *mut c_uchar = ptr::null_mut();
    let ret = 'bad: {
        if !section.is_null() {
            if cnf.is_null() {
                break 'bad ptr::null_mut();
            }
            // SAFETY: the caller's context and section name.
            sect = unsafe { X509V3_get_section(cnf, section) };
            if sect.is_null() {
                break 'bad ptr::null_mut();
            }
            // SAFETY: the section's values.
            for i in 0..unsafe { OPENSSL_sk_num(sect.cast()) } {
                // SAFETY: an index within them.
                let v = unsafe { OPENSSL_sk_value(sect.cast(), i) }.cast::<CONF_VALUE>();
                // SAFETY: a value of the section.
                let value = unsafe { v.as_ref() }.map_or(ptr::null(), |v| v.value.cast_const());
                // SAFETY: as above.
                let typ = unsafe { generate(value, cnf, depth + 1, perr) };
                if typ.is_null() {
                    break 'bad ptr::null_mut();
                }
                // SAFETY: the list; the new value.
                if unsafe { OPENSSL_sk_push(sk, typ.cast()) } == 0 {
                    // SAFETY: not taken.
                    unsafe { ASN1_TYPE_free(typ) };
                    break 'bad ptr::null_mut();
                }
            }
        }
        let derlen = if utype == V_ASN1_SET {
            // SAFETY: the list of values; a new buffer.
            unsafe { i2d_ASN1_SET_ANY(sk.cast(), &raw mut der) }
        } else {
            // SAFETY: as above.
            unsafe { i2d_ASN1_SEQUENCE_ANY(sk.cast(), &raw mut der) }
        };
        if derlen < 0 {
            break 'bad ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let ret = unsafe { ASN1_TYPE_new() };
        // SAFETY: new, or NULL.
        let Some(r) = (unsafe { ret.as_mut() }) else {
            break 'bad ptr::null_mut();
        };
        // SAFETY: a type.
        let s: *mut ASN1_STRING = unsafe { ASN1_STRING_type_new(utype) };
        // SAFETY: the new string, or NULL.
        let Some(sr) = (unsafe { s.as_mut() }) else {
            // SAFETY: made above.
            unsafe { ASN1_TYPE_free(ret) };
            break 'bad ptr::null_mut();
        };
        sr.data = der;
        sr.length = derlen;
        der = ptr::null_mut();
        r.value.asn1_string = s;
        r.type_ = utype;
        ret
    };
    // SAFETY: left over, or NULL.
    unsafe { mem::release(der.cast()) };
    // SAFETY: the list and its values.
    unsafe { OPENSSL_sk_pop_free(sk, Some(type_free)) };
    // SAFETY: the section, or NULL.
    unsafe { X509V3_section_free(cnf, sect) };
    ret
}

/// `generate_v3`.
///
/// # Safety
/// `str_` is NULL or a C string; `cnf` is NULL or a live context.
unsafe fn generate(
    str_: *const c_char,
    cnf: *mut X509V3_CTX,
    depth: c_int,
    perr: &mut c_int,
) -> *mut ASN1_TYPE {
    let mut arg = Arg {
        imp_tag: -1,
        imp_class: -1,
        utype: -1,
        format: FORMAT_ASCII,
        str_: ptr::null(),
        exp: Vec::new(),
    };
    if str_.is_null()
        // SAFETY: the caller's string; the callback and its argument.
        || unsafe {
            CONF_parse_list(
                str_,
                c_int::from(b','),
                1,
                Some(asn1_cb),
                (&raw mut arg).cast(),
            )
        } != 0
    {
        *perr = ASN1_R_UNKNOWN_TAG;
        return ptr::null_mut();
    }
    let ret = if arg.utype == V_ASN1_SEQUENCE || arg.utype == V_ASN1_SET {
        if cnf.is_null() {
            *perr = ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG;
            return ptr::null_mut();
        }
        if depth >= SEQ_MAX_DEPTH {
            *perr = ASN1_R_ILLEGAL_NESTED_TAGGING;
            return ptr::null_mut();
        }
        // SAFETY: the value (a section name), within the caller's string; the context.
        unsafe { multi(arg.utype, arg.str_, cnf, depth, perr) }
    } else {
        // SAFETY: as above.
        unsafe { str2type(arg.str_, arg.format, arg.utype) }
    };
    if ret.is_null() {
        return ptr::null_mut();
    }
    if arg.imp_tag == -1 && arg.exp.is_empty() {
        return ret;
    }
    // SAFETY: the value, re-tagged below.
    unsafe { retag(ret, &mut arg) }
}

/// The value with the implicit tag and the explicit tags and wrappers applied (it is freed).
///
/// # Safety
/// `ret` is a live value.
unsafe fn retag(ret: *mut ASN1_TYPE, arg: &mut Arg) -> *mut ASN1_TYPE {
    let mut orig: *mut c_uchar = ptr::null_mut();
    // SAFETY: the caller's value; a new buffer.
    let mut cpy_len = unsafe { i2d_ASN1_TYPE(ret, &raw mut orig) };
    // SAFETY: the caller's value.
    unsafe { ASN1_TYPE_free(ret) };
    if orig.is_null() {
        return ptr::null_mut();
    }
    let mut new_der: *mut c_uchar = ptr::null_mut();
    let out = 'err: {
        let mut cpy_start = orig.cast_const();
        let mut hdr_len: c_long = 0;
        let mut hdr_constructed = 0;
        let mut len;
        if arg.imp_tag != -1 {
            let (mut tag, mut class) = (0, 0);
            // SAFETY: the encoding, `cpy_len` long.
            let r = unsafe {
                ASN1_get_object(
                    &raw mut cpy_start,
                    &raw mut hdr_len,
                    &raw mut tag,
                    &raw mut class,
                    c_long::from(cpy_len),
                )
            };
            if r & 0x80 != 0 {
                break 'err ptr::null_mut();
            }
            // SAFETY: within the encoding.
            let used = unsafe { cpy_start.offset_from(orig) };
            cpy_len -= c_int::try_from(used).unwrap_or(cpy_len);
            if r & 0x1 != 0 {
                hdr_constructed = 2;
                hdr_len = 0;
            } else {
                hdr_constructed = r & V_ASN1_CONSTRUCTED;
            }
            let Ok(hl) = c_int::try_from(hdr_len) else {
                break 'err ptr::null_mut();
            };
            // SAFETY: no preconditions.
            len = unsafe { ASN1_object_size(0, hl, arg.imp_tag) };
            if len == -1 {
                break 'err ptr::null_mut();
            }
        } else {
            len = cpy_len;
        }
        for e in arg.exp.iter_mut().rev() {
            len = len.saturating_add(e.pad);
            e.len = c_long::from(len);
            // SAFETY: no preconditions.
            len = unsafe { ASN1_object_size(0, len, e.tag) };
            if len == -1 {
                break 'err ptr::null_mut();
            }
        }
        let Ok(total) = usize::try_from(len) else {
            break 'err ptr::null_mut();
        };
        new_der = mem::alloc(total).cast();
        if new_der.is_null() {
            break 'err ptr::null_mut();
        }
        let mut p = new_der;
        for e in &arg.exp {
            let Ok(el) = c_int::try_from(e.len) else {
                break 'err ptr::null_mut();
            };
            // SAFETY: room for the headers, as sized above.
            unsafe { ASN1_put_object(&raw mut p, e.constructed, el, e.tag, e.class) };
            if e.pad != 0 {
                // SAFETY: as above.
                unsafe { p.write(0) };
                // SAFETY: as above.
                p = unsafe { p.add(1) };
            }
        }
        if arg.imp_tag != -1 {
            if arg.imp_class == V_ASN1_UNIVERSAL
                && (arg.imp_tag == V_ASN1_SEQUENCE || arg.imp_tag == V_ASN1_SET)
            {
                hdr_constructed = V_ASN1_CONSTRUCTED;
            }
            let hl = c_int::try_from(hdr_len).unwrap_or(0);
            // SAFETY: as above.
            unsafe { ASN1_put_object(&raw mut p, hdr_constructed, hl, arg.imp_tag, arg.imp_class) };
        }
        let n = usize::try_from(cpy_len).unwrap_or(0);
        // SAFETY: the content, into the room left for it.
        unsafe { ptr::copy_nonoverlapping(cpy_start, p, n) };
        let mut cp = new_der.cast_const();
        // SAFETY: the new encoding, `len` long.
        unsafe { d2i_ASN1_TYPE(ptr::null_mut(), &raw mut cp, c_long::from(len)) }
    };
    // SAFETY: allocated above, or NULL.
    unsafe { mem::release(orig.cast()) };
    // SAFETY: as above.
    unsafe { mem::release(new_der.cast()) };
    out
}

ffi_export! {
    /// The value `str` describes, its SEQUENCE and SET sections from `cnf` (none if NULL), or
    /// NULL (with an `ERR_LIB_ASN1` error).
    ///
    /// # Safety
    /// `str` is NULL or a C string; `cnf` is NULL or a live context.
    pub unsafe extern "C" fn ASN1_generate_v3(str: *const c_char, cnf: *mut X509V3_CTX) -> *mut ASN1_TYPE
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        let mut e = 0;
        // SAFETY: the caller's guarantee.
        let ret = unsafe { generate(str, cnf, 0, &mut e) };
        if e != 0 {
            err::raise(ERR_LIB_ASN1, e, "ASN1_generate_v3");
        }
        ret
    }
}

ffi_export! {
    /// `ASN1_generate_v3` with the sections of the configuration `nconf` (none if NULL).
    ///
    /// # Safety
    /// `str` is NULL or a C string; `nconf` is NULL or a live configuration.
    pub unsafe extern "C" fn ASN1_generate_nconf(str: *const c_char, nconf: *mut CONF) -> *mut ASN1_TYPE
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        if nconf.is_null() {
            // SAFETY: the caller's guarantee.
            return unsafe { ASN1_generate_v3(str, ptr::null_mut()) };
        }
        // SAFETY: an all-zero context is an empty one, as OpenSSL's on the stack before
        // `X509V3_set_nconf`.
        let mut cnf: X509V3_CTX = unsafe { core::mem::zeroed() };
        // SAFETY: the context; the caller's configuration.
        unsafe { X509V3_set_nconf(&raw mut cnf, nconf) };
        // SAFETY: as above.
        unsafe { ASN1_generate_v3(str, &raw mut cnf) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strtoul_reads_as_c_does() {
        assert_eq!(strtoul10(b"12abc"), (12, 2));
        assert_eq!(strtoul10(b"  +7"), (7, 4));
        assert_eq!(strtoul10(b"-1"), (u64::MAX, 2));
        assert_eq!(strtoul10(b"x"), (0, 0));
        assert_eq!(strtoul10(b"99999999999999999999999"), (u64::MAX, 23));
    }

    /// docs/DEVIATIONS.md: a NULL string, which OpenSSL leaves its parser's type unset for,
    /// fails with `ASN1_R_UNKNOWN_TAG`.
    #[test]
    fn null_strings_fail() {
        err::take_all();
        // SAFETY: NULL, which it refuses.
        assert!(unsafe { ASN1_generate_v3(ptr::null(), ptr::null_mut()) }.is_null());
        let errors = err::take_all();
        assert_eq!(
            errors.last().map(|e| e.code),
            Some(err::pack(ERR_LIB_ASN1, ASN1_R_UNKNOWN_TAG))
        );
    }
}
