//! Decoding values by their items (`ASN1_item_d2i(3)`, `ASN1_item_d2i_ex`, `ASN1_item_ex_d2i`),
//! as OpenSSL's `tasn_dec.c` does: tags are checked against the templates, OPTIONAL fields and
//! CHOICE alternatives are tried in order, ANY DEFINED BY fields are decoded by their
//! selector, constructed strings are collected, SEQUENCE, SET, and non-universal ANY values are
//! kept whole, and the nesting is limited.
//!
//! The input is turned into a slice once, at the boundary, from the pointer and length the
//! caller passes; every read after that is bounded by it. Item functions an application
//! supplies get pointers into it, as in C, and are trusted to stay within the length they're
//! given. The header cache (`ASN1_TLC`) is kept as OpenSSL keeps it, since which errors a bad
//! input raises depends on it, but a cached header is used only where it fits the input.

use core::ffi::{c_char, c_int, c_long, c_uchar};
use core::ptr;

use rustyssl_abi::{
    ASN1_AFLG_BROKEN, ASN1_EXTERN_FUNCS, ASN1_ITEM, ASN1_ITYPE_CHOICE, ASN1_ITYPE_EXTERN,
    ASN1_ITYPE_MSTRING, ASN1_ITYPE_NDEF_SEQUENCE, ASN1_ITYPE_PRIMITIVE, ASN1_ITYPE_SEQUENCE,
    ASN1_OP_D2I_POST, ASN1_OP_D2I_PRE, ASN1_PRIMITIVE_FUNCS, ASN1_R_AUX_ERROR,
    ASN1_R_BAD_OBJECT_HEADER, ASN1_R_BAD_TEMPLATE, ASN1_R_BMPSTRING_IS_WRONG_LENGTH,
    ASN1_R_BOOLEAN_IS_WRONG_LENGTH, ASN1_R_EXPLICIT_LENGTH_MISMATCH,
    ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED, ASN1_R_FIELD_MISSING, ASN1_R_GENERALIZEDTIME_IS_TOO_SHORT,
    ASN1_R_ILLEGAL_NULL, ASN1_R_ILLEGAL_OPTIONAL_ANY, ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE,
    ASN1_R_ILLEGAL_PADDING, ASN1_R_ILLEGAL_TAGGED_ANY, ASN1_R_ILLEGAL_ZERO_CONTENT,
    ASN1_R_INVALID_BIT_STRING_BITS_LEFT, ASN1_R_MISSING_EOC, ASN1_R_MSTRING_NOT_UNIVERSAL,
    ASN1_R_MSTRING_WRONG_TAG, ASN1_R_NESTED_ASN1_STRING, ASN1_R_NESTED_TOO_DEEP,
    ASN1_R_NO_MATCHING_CHOICE_TYPE, ASN1_R_NULL_IS_WRONG_LENGTH, ASN1_R_SEQUENCE_LENGTH_MISMATCH,
    ASN1_R_SEQUENCE_NOT_CONSTRUCTED, ASN1_R_STRING_TOO_LONG, ASN1_R_STRING_TOO_SHORT,
    ASN1_R_TOO_LARGE, ASN1_R_TOO_LONG, ASN1_R_TOO_SMALL, ASN1_R_TYPE_NOT_CONSTRUCTED,
    ASN1_R_TYPE_NOT_PRIMITIVE, ASN1_R_UNEXPECTED_EOC, ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH,
    ASN1_R_UTCTIME_IS_TOO_SHORT, ASN1_R_WRONG_TAG, ASN1_STRING, ASN1_STRING_FLAG_BITS_LEFT,
    ASN1_TEMPLATE, ASN1_TFLG_ADB_MASK, ASN1_TFLG_EMBED, ASN1_TFLG_EXPTAG, ASN1_TFLG_IMPTAG,
    ASN1_TFLG_OPTIONAL, ASN1_TFLG_SET_OF, ASN1_TFLG_SK_MASK, ASN1_TFLG_TAG_CLASS, ASN1_TLC,
    ASN1_TYPE, ASN1_VALUE, ERR_LIB_ASN1, ERR_R_ASN1_LIB, ERR_R_CRYPTO_LIB, ERR_R_NESTED_ASN1_ERROR,
    ERR_R_PASSED_NULL_PARAMETER, OPENSSL_STACK, OSSL_LIB_CTX, V_ASN1_ANY, V_ASN1_BIT_STRING,
    V_ASN1_BMPSTRING, V_ASN1_BOOLEAN, V_ASN1_CONSTRUCTED, V_ASN1_ENUMERATED,
    V_ASN1_GENERALIZEDTIME, V_ASN1_INTEGER, V_ASN1_NEG, V_ASN1_NULL, V_ASN1_OBJECT, V_ASN1_OTHER,
    V_ASN1_SEQUENCE, V_ASN1_SET, V_ASN1_UNIVERSAL, V_ASN1_UNIVERSALSTRING, V_ASN1_UTCTIME,
};
use rustyssl_asn1::content::{self, BitStringError, IntegerError};
use rustyssl_asn1::der::HeaderError;

use super::free::{ASN1_item_ex_free, ASN1_item_free, template_free};
use super::new::{aux_callback, embed_new};
use super::{
    Pval, choice_selector, field_ptr, itype, long_to_int, set_choice_selector, template_flags,
    template_item, utype,
};
use crate::asn1::{any, read_header_in, string, text};
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects;
use crate::stack;

/// The deepest nesting of constructed values `asn1_item_embed_d2i` follows
/// (`ASN1_MAX_CONSTRUCTED_NEST`, private to `tasn_dec.c`).
const MAX_CONSTRUCTED_NEST: c_int = 30;

/// The deepest nesting of a constructed string's pieces (`ASN1_MAX_STRING_NEST`, private to
/// `tasn_dec.c`).
const MAX_STRING_NEST: c_int = 5;

/// The header cache behind an `ASN1_TLC *`, laid out as OpenSSL's private `ASN1_TLC_st`: the
/// last header read, kept while its tag hasn't matched a template, so that the next template
/// tried at the same place reads it from here.
#[repr(C)]
pub(crate) struct Tlc {
    valid: c_char,
    ret: c_int,
    plen: c_long,
    ptag: c_int,
    pclass: c_int,
    hdrlen: c_int,
}

impl Tlc {
    fn new() -> Self {
        Self {
            valid: 0,
            ret: 0,
            plen: 0,
            ptag: 0,
            pclass: 0,
            hdrlen: 0,
        }
    }
}

/// An `ASN1_TLC *`: NULL or a live cache.
type Ctx = *mut Tlc;

/// `asn1_tlc_clear`.
///
/// # Safety
/// `ctx` is NULL or a live cache.
unsafe fn tlc_clear(ctx: Ctx) {
    if !ctx.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { (*ctx).valid = 0 };
    }
}

/// Raises an ASN1 error from `function`.
#[track_caller]
fn raise(reason: c_int, function: &str) {
    err::raise(ERR_LIB_ASN1, reason, function);
}

/// Moves `input` on to where `rest` starts, keeping its end. `rest` lies within `input`.
fn advance(input: &mut &[u8], rest: &[u8]) {
    let offset = rest.as_ptr().addr().wrapping_sub(input.as_ptr().addr());
    *input = input.get(offset..).unwrap_or(&[]);
}

/// The octets from the start of `whole` to where `rest` starts.
fn consumed<'a>(whole: &'a [u8], rest: &[u8]) -> &'a [u8] {
    let offset = rest.as_ptr().addr().wrapping_sub(whole.as_ptr().addr());
    whole.get(..offset).unwrap_or(whole)
}

/// A header as `asn1_check_tlen` reports it.
struct Tlen {
    /// The content length (to the end of the input for the indefinite length).
    len: usize,
    tag: c_int,
    class: c_int,
    inf: bool,
    cst: bool,
}

/// What `asn1_check_tlen` found: a header, or (for an OPTIONAL one) not the expected tag.
enum Check {
    Found(Tlen),
    Absent,
}

/// `asn1_check_tlen`: reads the header at the start of `input` (all of it available), checking
/// its tag and class against `exptag` (if not negative) and `expclass`, through the cache.
/// Moves `input` past the header. `Err` after raising the error.
///
/// # Safety
/// `ctx` is NULL or a live cache.
unsafe fn check_tlen(
    input: &mut &[u8],
    exptag: c_int,
    expclass: c_int,
    opt: bool,
    ctx: Ctx,
) -> Result<Check, ()> {
    let fail = move |reason: c_int| {
        raise(reason, "asn1_check_tlen");
        // SAFETY: the caller's guarantee.
        unsafe { tlc_clear(ctx) };
        Err(())
    };
    let len = input.len();
    if len == 0 {
        return fail(ASN1_R_TOO_SMALL);
    }
    // SAFETY: the caller's guarantee.
    let cached = !ctx.is_null() && unsafe { (*ctx).valid } != 0;
    let (ret, plen, ptag, pclass, hdrlen) = if cached {
        // SAFETY: as above.
        let c = unsafe { &*ctx };
        (
            c.ret,
            c.plen,
            c.ptag,
            c.pclass,
            usize::try_from(c.hdrlen).unwrap_or(usize::MAX),
        )
    } else {
        let (ret, plen, ptag, pclass, hdrlen) = match read_header_in(input) {
            Ok(h) => {
                let mut ret = if h.constructed { V_ASN1_CONSTRUCTED } else { 0 };
                ret |= c_int::from(h.indefinite);
                if h.overrun {
                    ret |= crate::asn1::GET_ERROR;
                }
                (
                    ret,
                    c_long::try_from(h.length).unwrap_or(c_long::MAX),
                    h.tag,
                    c_int::from(h.class),
                    h.header_len,
                )
            }
            Err(HeaderError::TooSmall | HeaderError::Malformed { .. }) => {
                (crate::asn1::GET_ERROR, 0, 0, 0, 0)
            }
        };
        if !ctx.is_null() {
            // SAFETY: the caller's guarantee.
            let c = unsafe { &mut *ctx };
            *c = Tlc {
                valid: 1,
                ret,
                plen,
                ptag,
                pclass,
                hdrlen: c_int::try_from(hdrlen).unwrap_or(c_int::MAX),
            };
            let total = usize::try_from(plen)
                .unwrap_or(usize::MAX)
                .saturating_add(hdrlen);
            if ret & 0x81 == 0 && total > len {
                return fail(ASN1_R_TOO_LONG);
            }
        }
        (ret, plen, ptag, pclass, hdrlen)
    };
    if ret & crate::asn1::GET_ERROR != 0 {
        return fail(ASN1_R_BAD_OBJECT_HEADER);
    }
    // A cached header must fit where it is used.
    let Some(rest) = input.get(hdrlen..) else {
        return fail(ASN1_R_BAD_OBJECT_HEADER);
    };
    if exptag >= 0 {
        if exptag != ptag || expclass != pclass {
            if opt {
                return Ok(Check::Absent);
            }
            return fail(ASN1_R_WRONG_TAG);
        }
        // SAFETY: the caller's guarantee.
        unsafe { tlc_clear(ctx) };
    }
    let inf = ret & 1 != 0;
    let content_len = if inf {
        rest.len()
    } else {
        match usize::try_from(plen) {
            Ok(n) if n <= rest.len() => n,
            _ => return fail(ASN1_R_BAD_OBJECT_HEADER),
        }
    };
    *input = rest;
    Ok(Check::Found(Tlen {
        len: content_len,
        tag: ptag,
        class: pclass,
        inf,
        cst: ret & V_ASN1_CONSTRUCTED != 0,
    }))
}

/// What a decoding step returns: 1 for a value read, -1 for an OPTIONAL one absent, 0 for an
/// error (raised).
type Ret = c_int;

/// `asn1_item_embed_d2i`: decodes a value of `it` from `input` into `*pval`, moving `input`
/// past it.
///
/// # Safety
/// `pval` is a slot for a value of `it` (NULL, or a live value to decode into); `it` is a live
/// item whose tables and functions can be trusted; `ctx` is NULL or a live cache.
#[expect(clippy::too_many_arguments, reason = "OpenSSL's signature")]
unsafe fn embed_d2i(
    pval: Pval,
    input: &mut &[u8],
    it: *const ASN1_ITEM,
    tag: c_int,
    aclass: c_int,
    opt: bool,
    ctx: Ctx,
    depth: c_int,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> Ret {
    if pval.is_null() || it.is_null() {
        raise(ERR_R_PASSED_NULL_PARAMETER, "asn1_item_embed_d2i");
        return 0;
    }
    if input.is_empty() {
        raise(ASN1_R_TOO_SMALL, "asn1_item_embed_d2i");
        return 0;
    }
    let mut errtt: *const ASN1_TEMPLATE = ptr::null();
    // SAFETY: the caller's guarantee.
    let result = unsafe {
        embed_d2i_body(
            pval, input, it, tag, aclass, opt, ctx, depth, libctx, propq, &mut errtt,
        )
    };
    match result {
        Ok(ret) => ret,
        Err(aux) => {
            if aux {
                raise(ASN1_R_AUX_ERROR, "asn1_item_embed_d2i");
            }
            // SAFETY: a live item and, if any, one of its templates.
            let sname_ptr = unsafe { (*it).sname };
            // SAFETY: as above.
            let sname = unsafe { cstr(sname_ptr) };
            if errtt.is_null() {
                err::add_error_data([Some(&b"Type="[..]), sname]);
            } else {
                // SAFETY: as above.
                let field_ptr = unsafe { (*errtt).field_name };
                // SAFETY: as above.
                let field = unsafe { cstr(field_ptr) };
                err::add_error_data([Some(&b"Field="[..]), field, Some(&b", Type="[..]), sname]);
            }
            0
        }
    }
}

/// A C string's bytes, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a string.
unsafe fn cstr<'a>(s: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    unsafe { super::cstr_bytes(s) }
}

/// The body of [`embed_d2i`]: `Err(aux)` goes to OpenSSL's `err` label, through `auxerr` if
/// `aux`.
///
/// # Safety
/// As for [`embed_d2i`].
#[expect(clippy::too_many_arguments, reason = "OpenSSL's signature")]
unsafe fn embed_d2i_body(
    pval: Pval,
    input: &mut &[u8],
    it: *const ASN1_ITEM,
    tag: c_int,
    aclass: c_int,
    opt: bool,
    ctx: Ctx,
    depth: c_int,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    errtt: &mut *const ASN1_TEMPLATE,
) -> Result<Ret, bool> {
    // SAFETY: the caller's guarantee.
    let item = unsafe { &*it };
    // SAFETY: as above.
    let kind = unsafe { itype(it) };
    let depth = depth.wrapping_add(1);
    if depth > MAX_CONSTRUCTED_NEST {
        raise(ASN1_R_NESTED_TOO_DEEP, "asn1_item_embed_d2i");
        return Err(false);
    }
    match kind {
        ASN1_ITYPE_PRIMITIVE => {
            if !item.templates.is_null() {
                if tag != -1 || opt {
                    raise(
                        ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE,
                        "asn1_item_embed_d2i",
                    );
                    return Err(false);
                }
                // SAFETY: the item's template.
                return Ok(unsafe {
                    template_ex_d2i(pval, input, item.templates, opt, ctx, depth, libctx, propq)
                });
            }
            // SAFETY: the caller's guarantee.
            Ok(unsafe { d2i_ex_primitive(pval, input, it, tag, aclass, opt, ctx) })
        }
        ASN1_ITYPE_MSTRING => {
            if tag != -1 {
                raise(ASN1_R_BAD_TEMPLATE, "asn1_item_embed_d2i");
                return Err(false);
            }
            let mut p = *input;
            // SAFETY: the caller's guarantee.
            let Ok(Check::Found(h)) = (unsafe { check_tlen(&mut p, -1, 0, true, ctx) }) else {
                raise(ERR_R_NESTED_ASN1_ERROR, "asn1_item_embed_d2i");
                return Err(false);
            };
            if h.class != V_ASN1_UNIVERSAL {
                if opt {
                    return Ok(-1);
                }
                raise(ASN1_R_MSTRING_NOT_UNIVERSAL, "asn1_item_embed_d2i");
                return Err(false);
            }
            // SAFETY: no preconditions.
            let bit = unsafe { text::ASN1_tag2bit(h.tag) };
            if bit & item.utype.cast_unsigned() == 0 {
                if opt {
                    return Ok(-1);
                }
                raise(ASN1_R_MSTRING_WRONG_TAG, "asn1_item_embed_d2i");
                return Err(false);
            }
            // SAFETY: the caller's guarantee.
            Ok(unsafe { d2i_ex_primitive(pval, input, it, h.tag, 0, false, ctx) })
        }
        ASN1_ITYPE_EXTERN => {
            // SAFETY: an extern item's funcs; OpenSSL calls them unchecked.
            let ef = unsafe { super::funcs::<ASN1_EXTERN_FUNCS>(it) };
            let len = c_long::try_from(input.len()).unwrap_or(c_long::MAX);
            let mut p: *const c_uchar = input.as_ptr();
            let opt = c_char::from(opt);
            let ret = match (
                ef.and_then(|ef| ef.asn1_ex_d2i_ex),
                ef.and_then(|ef| ef.asn1_ex_d2i),
            ) {
                (Some(d2i_ex), _) => {
                    // SAFETY: the item's own function, given the input it may read.
                    unsafe {
                        d2i_ex(
                            pval,
                            &raw mut p,
                            len,
                            it,
                            tag,
                            aclass,
                            opt,
                            ctx.cast(),
                            libctx,
                            propq,
                        )
                    }
                }
                (None, Some(d2i)) => {
                    // SAFETY: as above.
                    unsafe { d2i(pval, &raw mut p, len, it, tag, aclass, opt, ctx.cast()) }
                }
                (None, None) => 0,
            };
            let used = p.addr().wrapping_sub(input.as_ptr().addr());
            match input.get(used..) {
                Some(rest) => *input = rest,
                // An item function that read past its input: refused rather than followed.
                None => {
                    err::raise(
                        ERR_LIB_ASN1,
                        rustyssl_abi::ERR_R_INTERNAL_ERROR,
                        "asn1_item_embed_d2i",
                    );
                    return Ok(0);
                }
            }
            Ok(ret)
        }
        ASN1_ITYPE_CHOICE => {
            if tag != -1 {
                raise(ASN1_R_BAD_TEMPLATE, "asn1_item_embed_d2i");
                return Err(false);
            }
            // SAFETY: a CHOICE item.
            let callback = unsafe { aux_callback(it) };
            if let Some(cb) = callback {
                // SAFETY: the application's callback.
                if unsafe { cb(ASN1_OP_D2I_PRE, pval, it, ptr::null_mut()) } == 0 {
                    return Err(true);
                }
            }
            // SAFETY: the caller's slot.
            if unsafe { pval.read() }.is_null() {
                // SAFETY: as above.
                if unsafe { embed_new(pval, it, false, libctx, propq) } == 0 {
                    raise(ERR_R_NESTED_ASN1_ERROR, "asn1_item_embed_d2i");
                    return Err(false);
                }
            } else {
                // SAFETY: a live CHOICE structure.
                let i = unsafe { choice_selector(pval, it) };
                if let Ok(index) = usize::try_from(i)
                    && c_long::from(i) < item.tcount
                {
                    let tt = item.templates.wrapping_add(index);
                    // SAFETY: a template of the item.
                    let field = unsafe { field_ptr(pval, tt) };
                    // SAFETY: as above.
                    unsafe { template_free(field, tt) };
                    // SAFETY: as above.
                    unsafe { set_choice_selector(pval, -1, it) };
                }
            }
            let mut p = *input;
            let count = usize::try_from(item.tcount).unwrap_or(0);
            let mut chosen = None;
            for i in 0..count {
                let tt = item.templates.wrapping_add(i);
                // SAFETY: a template of the item, for a field of the structure.
                let field = unsafe { field_ptr(pval, tt) };
                // SAFETY: as above.
                let ret =
                    unsafe { template_ex_d2i(field, &mut p, tt, true, ctx, depth, libctx, propq) };
                if ret == -1 {
                    continue;
                }
                if ret > 0 {
                    chosen = Some(i);
                    break;
                }
                // SAFETY: as above.
                unsafe { template_free(field, tt) };
                *errtt = tt;
                raise(ERR_R_NESTED_ASN1_ERROR, "asn1_item_embed_d2i");
                return Err(false);
            }
            let Some(i) = chosen else {
                if opt {
                    // SAFETY: the structure made or reused above.
                    unsafe { ASN1_item_ex_free(pval, it) };
                    return Ok(-1);
                }
                raise(ASN1_R_NO_MATCHING_CHOICE_TYPE, "asn1_item_embed_d2i");
                return Err(false);
            };
            // SAFETY: as above.
            unsafe { set_choice_selector(pval, c_int::try_from(i).unwrap_or(-1), it) };
            if let Some(cb) = callback {
                // SAFETY: as above.
                if unsafe { cb(ASN1_OP_D2I_POST, pval, it, ptr::null_mut()) } == 0 {
                    return Err(true);
                }
            }
            *input = p;
            Ok(1)
        }
        ASN1_ITYPE_NDEF_SEQUENCE | ASN1_ITYPE_SEQUENCE => {
            let whole = *input;
            let mut p = *input;
            let (tag, aclass) = if tag == -1 {
                (V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL)
            } else {
                (tag, aclass)
            };
            // SAFETY: the caller's guarantee.
            let h = match unsafe { check_tlen(&mut p, tag, aclass, opt, ctx) } {
                Err(()) => {
                    raise(ERR_R_NESTED_ASN1_ERROR, "asn1_item_embed_d2i");
                    return Err(false);
                }
                Ok(Check::Absent) => return Ok(-1),
                Ok(Check::Found(h)) => h,
            };
            // SAFETY: a SEQUENCE's funcs are its aux data.
            let aux = unsafe { super::aux(it) };
            // SAFETY: as above.
            let broken = !aux.is_null() && unsafe { (*aux).flags } & ASN1_AFLG_BROKEN != 0;
            let mut seq_eoc = h.inf;
            let seq_nolen = broken || h.inf;
            // The content: to the end of the input when broken or indefinite.
            let mut c = if broken {
                p
            } else {
                p.get(..h.len).unwrap_or(p)
            };
            if !h.cst {
                raise(ASN1_R_SEQUENCE_NOT_CONSTRUCTED, "asn1_item_embed_d2i");
                return Err(false);
            }
            // SAFETY: the caller's slot.
            let absent = unsafe { pval.read() }.is_null();
            // SAFETY: as above.
            if absent && unsafe { embed_new(pval, it, false, libctx, propq) } == 0 {
                raise(ERR_R_NESTED_ASN1_ERROR, "asn1_item_embed_d2i");
                return Err(false);
            }
            // SAFETY: a SEQUENCE item.
            let callback = unsafe { aux_callback(it) };
            if let Some(cb) = callback {
                // SAFETY: the application's callback.
                if unsafe { cb(ASN1_OP_D2I_PRE, pval, it, ptr::null_mut()) } == 0 {
                    return Err(true);
                }
            }
            let count = usize::try_from(item.tcount).unwrap_or(0);
            for i in 0..count {
                let tt = item.templates.wrapping_add(i);
                // SAFETY: a template of the item.
                if unsafe { template_flags(tt) } & ASN1_TFLG_ADB_MASK != 0 {
                    // SAFETY: the structure.
                    let structure = unsafe { pval.read() };
                    // SAFETY: as above.
                    let seqtt = unsafe { super::do_adb(structure, tt, false) };
                    if seqtt.is_null() {
                        continue;
                    }
                    // SAFETY: as above.
                    let field = unsafe { field_ptr(pval, seqtt) };
                    // SAFETY: as above.
                    unsafe { template_free(field, seqtt) };
                }
            }
            let mut i = 0;
            while i < count {
                let tt = item.templates.wrapping_add(i);
                // SAFETY: the structure.
                let structure = unsafe { pval.read() };
                // SAFETY: as above, and a template of the item.
                let seqtt = unsafe { super::do_adb(structure, tt, true) };
                if seqtt.is_null() {
                    return Err(false);
                }
                // SAFETY: as above.
                let field = unsafe { field_ptr(pval, seqtt) };
                if c.is_empty() {
                    break;
                }
                if content::is_eoc(c) {
                    if !seq_eoc {
                        raise(ASN1_R_UNEXPECTED_EOC, "asn1_item_embed_d2i");
                        return Err(false);
                    }
                    c = c.get(2..).unwrap_or(&[]);
                    seq_eoc = false;
                    break;
                }
                // SAFETY: as above.
                let optional = unsafe { template_flags(seqtt) } & ASN1_TFLG_OPTIONAL != 0;
                let isopt = i != count.wrapping_sub(1) && optional;
                // SAFETY: as above.
                let ret = unsafe {
                    template_ex_d2i(field, &mut c, seqtt, isopt, ctx, depth, libctx, propq)
                };
                if ret == 0 {
                    *errtt = seqtt;
                    return Err(false);
                }
                if ret == -1 {
                    // SAFETY: as above.
                    unsafe { template_free(field, seqtt) };
                }
                i = i.wrapping_add(1);
            }
            if seq_eoc {
                if !content::is_eoc(c) {
                    raise(ASN1_R_MISSING_EOC, "asn1_item_embed_d2i");
                    return Err(false);
                }
                c = c.get(2..).unwrap_or(&[]);
            }
            if !seq_nolen && !c.is_empty() {
                raise(ASN1_R_SEQUENCE_LENGTH_MISMATCH, "asn1_item_embed_d2i");
                return Err(false);
            }
            while i < count {
                let tt = item.templates.wrapping_add(i);
                // SAFETY: the structure.
                let structure = unsafe { pval.read() };
                // SAFETY: as above.
                let seqtt = unsafe { super::do_adb(structure, tt, true) };
                if seqtt.is_null() {
                    return Err(false);
                }
                // SAFETY: as above.
                if unsafe { template_flags(seqtt) } & ASN1_TFLG_OPTIONAL != 0 {
                    // SAFETY: as above.
                    let field = unsafe { field_ptr(pval, seqtt) };
                    // SAFETY: as above.
                    unsafe { template_free(field, seqtt) };
                } else {
                    *errtt = seqtt;
                    raise(ASN1_R_FIELD_MISSING, "asn1_item_embed_d2i");
                    return Err(false);
                }
                i = i.wrapping_add(1);
            }
            // SAFETY: as above.
            if unsafe { super::enc_save(pval, consumed(whole, c), it) } == 0 {
                return Err(true);
            }
            if let Some(cb) = callback {
                // SAFETY: as above.
                if unsafe { cb(ASN1_OP_D2I_POST, pval, it, ptr::null_mut()) } == 0 {
                    return Err(true);
                }
            }
            advance(input, c);
            Ok(1)
        }
        _ => Ok(0),
    }
}

/// `asn1_template_ex_d2i`: a template's field, inside its EXPLICIT tag if it has one.
///
/// # Safety
/// `val` is the field's slot (or the field, if embedded); `tt` is a live template; `ctx` is
/// NULL or a live cache.
#[expect(clippy::too_many_arguments, reason = "OpenSSL's signature")]
unsafe fn template_ex_d2i(
    val: Pval,
    input: &mut &[u8],
    tt: *const ASN1_TEMPLATE,
    opt: bool,
    ctx: Ctx,
    depth: c_int,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> Ret {
    if val.is_null() {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let flags = unsafe { template_flags(tt) };
    if flags & ASN1_TFLG_EXPTAG == 0 {
        // SAFETY: as above.
        return unsafe { template_noexp_d2i(val, input, tt, opt, ctx, depth, libctx, propq) };
    }
    let aclass = flags & ASN1_TFLG_TAG_CLASS;
    let mut p = *input;
    // SAFETY: as above.
    let tag = long_to_int(unsafe { (*tt).tag });
    // SAFETY: as above.
    let h = match unsafe { check_tlen(&mut p, tag, aclass, opt, ctx) } {
        Err(()) => {
            raise(ERR_R_NESTED_ASN1_ERROR, "asn1_template_ex_d2i");
            return 0;
        }
        Ok(Check::Absent) => return -1,
        Ok(Check::Found(h)) => h,
    };
    if !h.cst {
        raise(ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED, "asn1_template_ex_d2i");
        return 0;
    }
    let mut c = p.get(..h.len).unwrap_or(p);
    // SAFETY: as above.
    if unsafe { template_noexp_d2i(val, &mut c, tt, false, ctx, depth, libctx, propq) } == 0 {
        raise(ERR_R_NESTED_ASN1_ERROR, "asn1_template_ex_d2i");
        return 0;
    }
    if h.inf {
        if !content::is_eoc(c) {
            raise(ASN1_R_MISSING_EOC, "asn1_template_ex_d2i");
            return 0;
        }
        c = c.get(2..).unwrap_or(&[]);
    } else if !c.is_empty() {
        raise(ASN1_R_EXPLICIT_LENGTH_MISMATCH, "asn1_template_ex_d2i");
        return 0;
    }
    advance(input, c);
    1
}

/// `asn1_template_noexp_d2i`: a template's field: a SET OF or SEQUENCE OF, or one value with
/// the template's IMPLICIT tag or none.
///
/// # Safety
/// As for [`template_ex_d2i`].
#[expect(clippy::too_many_arguments, reason = "OpenSSL's signature")]
unsafe fn template_noexp_d2i(
    val: Pval,
    input: &mut &[u8],
    tt: *const ASN1_TEMPLATE,
    opt: bool,
    ctx: Ctx,
    depth: c_int,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> Ret {
    if val.is_null() {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let flags = unsafe { template_flags(tt) };
    // SAFETY: as above.
    let it = unsafe { template_item(tt) };
    // SAFETY: as above.
    let tag = long_to_int(unsafe { (*tt).tag });
    let aclass = flags & ASN1_TFLG_TAG_CLASS;
    let mut tval: *mut ASN1_VALUE = val.cast();
    let val = if flags & ASN1_TFLG_EMBED != 0 {
        &raw mut tval
    } else {
        val
    };
    let mut p = *input;

    if flags & ASN1_TFLG_SK_MASK != 0 {
        let (sktag, skaclass) = if flags & ASN1_TFLG_IMPTAG != 0 {
            (tag, aclass)
        } else if flags & ASN1_TFLG_SET_OF != 0 {
            (V_ASN1_SET, V_ASN1_UNIVERSAL)
        } else {
            (V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL)
        };
        // SAFETY: the caller's guarantee.
        let h = match unsafe { check_tlen(&mut p, sktag, skaclass, opt, ctx) } {
            Err(()) => {
                raise(ERR_R_NESTED_ASN1_ERROR, "asn1_template_noexp_d2i");
                return 0;
            }
            Ok(Check::Absent) => return -1,
            Ok(Check::Found(h)) => h,
        };
        // SAFETY: the field's slot.
        let mut sk: *mut OPENSSL_STACK = unsafe { val.read() }.cast();
        if sk.is_null() {
            // SAFETY: no preconditions.
            sk = unsafe { stack::OPENSSL_sk_new_null() };
            // SAFETY: the field's slot.
            unsafe { val.write(sk.cast()) };
        } else {
            // SAFETY: a live stack of values of the item.
            while unsafe { stack::OPENSSL_sk_num(sk) } > 0 {
                // SAFETY: as above.
                let mut vtmp: *mut ASN1_VALUE = unsafe { stack::OPENSSL_sk_pop(sk) }.cast();
                // SAFETY: an element, a value of the item.
                unsafe { ASN1_item_ex_free(&raw mut vtmp, it) };
            }
        }
        if sk.is_null() {
            raise(ERR_R_CRYPTO_LIB, "asn1_template_noexp_d2i");
            return 0;
        }
        let mut c = p.get(..h.len).unwrap_or(p);
        let mut sk_eoc = h.inf;
        while !c.is_empty() {
            if content::is_eoc(c) {
                if !sk_eoc {
                    raise(ASN1_R_UNEXPECTED_EOC, "asn1_template_noexp_d2i");
                    return 0;
                }
                c = c.get(2..).unwrap_or(&[]);
                sk_eoc = false;
                break;
            }
            let mut skfield: *mut ASN1_VALUE = ptr::null_mut();
            // SAFETY: a local slot for a value of the item.
            let ret = unsafe {
                embed_d2i(
                    &raw mut skfield,
                    &mut c,
                    it,
                    -1,
                    0,
                    false,
                    ctx,
                    depth,
                    libctx,
                    propq,
                )
            };
            if ret <= 0 {
                raise(ERR_R_NESTED_ASN1_ERROR, "asn1_template_noexp_d2i");
                // SAFETY: what was decoded, if anything.
                unsafe { ASN1_item_free(skfield, it) };
                return 0;
            }
            // SAFETY: a live stack; the value is given to it.
            if unsafe { stack::OPENSSL_sk_push(sk, skfield.cast()) } == 0 {
                raise(ERR_R_CRYPTO_LIB, "asn1_template_noexp_d2i");
                // SAFETY: the value decoded.
                unsafe { ASN1_item_free(skfield, it) };
                return 0;
            }
        }
        if sk_eoc {
            raise(ASN1_R_MISSING_EOC, "asn1_template_noexp_d2i");
            return 0;
        }
        advance(input, c);
        return 1;
    }
    let (tag, aclass) = if flags & ASN1_TFLG_IMPTAG != 0 {
        (tag, aclass)
    } else {
        (-1, 0)
    };
    // SAFETY: the caller's guarantee.
    let ret = unsafe { embed_d2i(val, &mut p, it, tag, aclass, opt, ctx, depth, libctx, propq) };
    if ret == 0 {
        raise(ERR_R_NESTED_ASN1_ERROR, "asn1_template_noexp_d2i");
        return 0;
    }
    if ret == -1 {
        return -1;
    }
    *input = p;
    1
}

/// Content octets for `asn1_ex_c2i`: within the input, or collected from a constructed string
/// into a block from this allocator (null-terminated), which a string may take.
struct Content<'a> {
    octets: &'a [u8],
    /// The collected block, while still owned here.
    block: *mut c_uchar,
}

impl Drop for Content<'_> {
    fn drop(&mut self) {
        // SAFETY: a block from this allocator, not given away.
        unsafe { mem::release(self.block.cast()) };
    }
}

/// `asn1_d2i_ex_primitive`: a primitive's header and content, decoded into `*pval`.
///
/// # Safety
/// As for [`embed_d2i`], for a primitive or MSTRING item.
unsafe fn d2i_ex_primitive(
    pval: Pval,
    input: &mut &[u8],
    it: *const ASN1_ITEM,
    tag: c_int,
    aclass: c_int,
    opt: bool,
    ctx: Ctx,
) -> Ret {
    if pval.is_null() {
        raise(ASN1_R_ILLEGAL_NULL, "asn1_d2i_ex_primitive");
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let mstring = unsafe { itype(it) } == ASN1_ITYPE_MSTRING;
    // SAFETY: as above.
    let item_utype = unsafe { utype(it) };
    let (mut utype, mut tag) = if mstring {
        (tag, -1)
    } else {
        (item_utype, tag)
    };
    let mut aclass = aclass;
    if utype == V_ASN1_ANY {
        if tag >= 0 {
            raise(ASN1_R_ILLEGAL_TAGGED_ANY, "asn1_d2i_ex_primitive");
            return 0;
        }
        if opt {
            raise(ASN1_R_ILLEGAL_OPTIONAL_ANY, "asn1_d2i_ex_primitive");
            return 0;
        }
        let mut p = *input;
        // SAFETY: the caller's guarantee.
        let Ok(Check::Found(h)) = (unsafe { check_tlen(&mut p, -1, 0, false, ctx) }) else {
            raise(ERR_R_NESTED_ASN1_ERROR, "asn1_d2i_ex_primitive");
            return 0;
        };
        utype = if h.class == V_ASN1_UNIVERSAL {
            h.tag
        } else {
            V_ASN1_OTHER
        };
    }
    if tag == -1 {
        tag = utype;
        aclass = V_ASN1_UNIVERSAL;
    }
    let mut p = *input;
    // SAFETY: the caller's guarantee.
    let h = match unsafe { check_tlen(&mut p, tag, aclass, opt, ctx) } {
        Err(()) => {
            raise(ERR_R_NESTED_ASN1_ERROR, "asn1_d2i_ex_primitive");
            return 0;
        }
        Ok(Check::Absent) => return -1,
        Ok(Check::Found(h)) => h,
    };
    let content = if utype == V_ASN1_SEQUENCE || utype == V_ASN1_SET || utype == V_ASN1_OTHER {
        if utype == V_ASN1_OTHER {
            // SAFETY: the caller's guarantee.
            unsafe { tlc_clear(ctx) };
        } else if !h.cst {
            raise(ASN1_R_TYPE_NOT_CONSTRUCTED, "asn1_d2i_ex_primitive");
            return 0;
        }
        // The whole encoding, header included.
        if h.inf {
            let Ok(()) = find_end(&mut p, true) else {
                return 0;
            };
        } else {
            p = p.get(h.len..).unwrap_or(&[]);
        }
        Content {
            octets: consumed(input, p),
            block: ptr::null_mut(),
        }
    } else if h.cst {
        if matches!(
            utype,
            V_ASN1_NULL | V_ASN1_BOOLEAN | V_ASN1_OBJECT | V_ASN1_INTEGER | V_ASN1_ENUMERATED
        ) {
            raise(ASN1_R_TYPE_NOT_PRIMITIVE, "asn1_d2i_ex_primitive");
            return 0;
        }
        let mut buf = Vec::new();
        let mut c = p.get(..h.len).unwrap_or(p);
        let Ok(()) = collect(&mut buf, &mut c, h.inf, 0) else {
            return 0;
        };
        advance(&mut p, c);
        let block: *mut c_uchar = mem::alloc(buf.len().saturating_add(1)).cast();
        if block.is_null() {
            raise(rustyssl_abi::ERR_R_BUF_LIB, "asn1_d2i_ex_primitive");
            return 0;
        }
        // SAFETY: a new block with room for the octets and a NUL.
        unsafe { ptr::copy_nonoverlapping(buf.as_ptr(), block, buf.len()) };
        // SAFETY: as above, within the block.
        unsafe { block.wrapping_add(buf.len()).write(0) };
        // SAFETY: the block holds the octets.
        let octets = unsafe { core::slice::from_raw_parts(block, buf.len()) };
        Content { octets, block }
    } else {
        let octets = p.get(..h.len).unwrap_or(&[]);
        p = p.get(h.len..).unwrap_or(&[]);
        Content {
            octets,
            block: ptr::null_mut(),
        }
    };
    let mut content = content;
    // SAFETY: the caller's guarantee.
    if !unsafe { ex_c2i(pval, &mut content, utype, it) } {
        return 0;
    }
    *input = p;
    1
}

/// Raises the error for refused INTEGER content.
fn raise_integer(e: IntegerError, function: &str) {
    let reason = match e {
        IntegerError::ZeroContent => ASN1_R_ILLEGAL_ZERO_CONTENT,
        IntegerError::IllegalPadding => ASN1_R_ILLEGAL_PADDING,
        IntegerError::TooLarge => ASN1_R_TOO_LARGE,
    };
    raise(reason, function);
}

/// `asn1_ex_c2i`: content octets of type `utype` into `*pval` (for an ANY, into the
/// `ASN1_TYPE` there). A string takes a collected block.
///
/// # Safety
/// As for [`embed_d2i`].
unsafe fn ex_c2i(
    pval: Pval,
    content: &mut Content<'_>,
    utype: c_int,
    it: *const ASN1_ITEM,
) -> bool {
    let cont = content.octets;
    let ilen = c_int::try_from(cont.len());
    // SAFETY: the caller's guarantee.
    let pf = unsafe { super::funcs::<ASN1_PRIMITIVE_FUNCS>(it) };
    if let Some(c2i) = pf.and_then(|pf| pf.prim_c2i) {
        let Ok(ilen) = ilen else {
            raise(ASN1_R_TOO_LONG, "asn1_ex_c2i");
            return false;
        };
        let mut free_cont = c_char::from(!content.block.is_null());
        // SAFETY: the item's own function, given the content.
        let ret = unsafe { c2i(pval, cont.as_ptr(), ilen, utype, &raw mut free_cont, it) };
        if free_cont == 0 {
            // Taken by the function.
            content.block = ptr::null_mut();
        }
        return ret != 0;
    }
    let mut pval = pval;
    let mut opval: Pval = ptr::null_mut();
    let mut typ: *mut ASN1_TYPE = ptr::null_mut();
    // SAFETY: the caller's guarantee.
    if unsafe { super::utype(it) } == V_ASN1_ANY {
        // SAFETY: the caller's slot.
        typ = unsafe { pval.read() }.cast();
        if typ.is_null() {
            // SAFETY: no preconditions.
            let any_it = unsafe { super::items::ASN1_ANY_it() };
            // SAFETY: the ANY item.
            typ = unsafe { super::new::ASN1_item_new(any_it) }.cast();
            if typ.is_null() {
                return false;
            }
            // SAFETY: the caller's slot.
            unsafe { pval.write(typ.cast()) };
        }
        // SAFETY: a live ASN1_TYPE.
        if utype != unsafe { (*typ).type_ } {
            // SAFETY: as above.
            unsafe { any::ASN1_TYPE_set(typ, utype, ptr::null_mut()) };
        }
        opval = pval;
        // SAFETY: as above; its value's slot.
        pval = unsafe { (&raw mut (*typ).value).cast() };
    }
    // SAFETY: the slots above.
    let ok = unsafe { c2i_value(pval, content, utype, ilen) };
    if ok {
        if !typ.is_null() && utype == V_ASN1_NULL {
            // SAFETY: a live ASN1_TYPE.
            let value = unsafe { &mut (*typ).value };
            value.ptr = ptr::null_mut();
        }
        return true;
    }
    if !typ.is_null() {
        // SAFETY: the ANY's ASN1_TYPE, from this allocator, freed as OpenSSL frees it.
        unsafe { any::free_value(typ) };
        // SAFETY: as above.
        unsafe { mem::release(typ.cast()) };
    }
    if !opval.is_null() {
        // SAFETY: the caller's slot.
        unsafe { opval.write(ptr::null_mut()) };
    }
    false
}

/// The value part of `asn1_ex_c2i`, by type.
///
/// # Safety
/// `pval` is a slot for a value of `utype` (a BOOLEAN's is its `int`).
unsafe fn c2i_value(
    pval: Pval,
    content: &mut Content<'_>,
    utype: c_int,
    ilen: Result<c_int, core::num::TryFromIntError>,
) -> bool {
    let cont = content.octets;
    match utype {
        V_ASN1_OBJECT => {
            if ilen.is_err() {
                return false;
            }
            // SAFETY: an OBJECT's slot.
            !unsafe { objects::c2i(pval.cast(), cont) }.is_null()
        }
        V_ASN1_NULL => {
            if !cont.is_empty() {
                raise(ASN1_R_NULL_IS_WRONG_LENGTH, "asn1_ex_c2i");
                return false;
            }
            // SAFETY: the slot; NULL's value is the pointer 1.
            unsafe { pval.write(ptr::without_provenance_mut(1)) };
            true
        }
        V_ASN1_BOOLEAN => {
            let [b] = cont else {
                raise(ASN1_R_BOOLEAN_IS_WRONG_LENGTH, "asn1_ex_c2i");
                return false;
            };
            // SAFETY: a BOOLEAN's slot is its `int`.
            unsafe { pval.cast::<c_int>().write(c_int::from(*b)) };
            true
        }
        V_ASN1_BIT_STRING => {
            let result = content::bit_string(cont);
            let reason = match (&result, ilen) {
                (Err(BitStringError::TooShort), _) => Some(ASN1_R_STRING_TOO_SHORT),
                (_, Err(_)) => Some(ASN1_R_STRING_TOO_LONG),
                (Err(BitStringError::BitsLeft), _) => Some(ASN1_R_INVALID_BIT_STRING_BITS_LEFT),
                (Ok(_), Ok(_)) => None,
            };
            let (Some(()), Ok((bits, octets))) = (reason.is_none().then_some(()), result) else {
                if let Some(reason) = reason {
                    raise(reason, "ossl_c2i_ASN1_BIT_STRING");
                }
                return false;
            };
            // SAFETY: a BIT STRING's slot.
            let Some(str) = (unsafe { string_slot(pval, V_ASN1_BIT_STRING) }) else {
                return false;
            };
            // SAFETY: a live string.
            let s = unsafe { &mut *str };
            s.flags &= !0x07;
            s.flags |= c_long::from(ASN1_STRING_FLAG_BITS_LEFT) | c_long::from(bits & 0x07);
            // The octets in a block of their own size, none for no octets, as OpenSSL stores
            // them.
            let block: *mut c_uchar = if octets.is_empty() {
                ptr::null_mut()
            } else {
                mem::alloc(octets.len()).cast()
            };
            if !octets.is_empty() {
                if block.is_null() {
                    return false;
                }
                // SAFETY: a new block of the octets' size.
                unsafe { ptr::copy_nonoverlapping(octets.as_ptr(), block, octets.len()) };
            }
            let length = c_int::try_from(octets.len()).unwrap_or(0);
            // SAFETY: a live string, given the block.
            unsafe { string::ASN1_STRING_set0(str, block.cast(), length) };
            s.type_ = V_ASN1_BIT_STRING;
            true
        }
        V_ASN1_INTEGER | V_ASN1_ENUMERATED => {
            let (magnitude, negative) = match content::integer(cont) {
                Ok(m) => m,
                Err(e) => {
                    raise_integer(e, "c2i_ibuf");
                    return false;
                }
            };
            // SAFETY: an INTEGER's slot.
            let Some(str) = (unsafe { string_slot(pval, V_ASN1_INTEGER) }) else {
                return false;
            };
            let length = c_int::try_from(magnitude.len()).unwrap_or(c_int::MAX);
            // SAFETY: a live string.
            if unsafe { string::set(str, magnitude.as_ptr().cast(), length) } == 0 {
                raise(ERR_R_ASN1_LIB, "ossl_c2i_ASN1_INTEGER");
                return false;
            }
            // SAFETY: as above.
            let s = unsafe { &mut *str };
            let sign = if negative { V_ASN1_NEG } else { 0 };
            s.type_ = utype | sign;
            true
        }
        _ => {
            let Ok(ilen) = ilen else {
                raise(ASN1_R_TOO_LONG, "asn1_ex_c2i");
                return false;
            };
            let reason = match utype {
                V_ASN1_BMPSTRING if ilen & 1 != 0 => Some(ASN1_R_BMPSTRING_IS_WRONG_LENGTH),
                V_ASN1_UNIVERSALSTRING if ilen & 3 != 0 => {
                    Some(ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH)
                }
                V_ASN1_GENERALIZEDTIME if ilen < 15 => Some(ASN1_R_GENERALIZEDTIME_IS_TOO_SHORT),
                V_ASN1_UTCTIME if ilen < 13 => Some(ASN1_R_UTCTIME_IS_TOO_SHORT),
                _ => None,
            };
            if let Some(reason) = reason {
                raise(reason, "asn1_ex_c2i");
                return false;
            }
            // SAFETY: the slot.
            let mut str: *mut ASN1_STRING = unsafe { pval.read() }.cast();
            if str.is_null() {
                str = string::type_new(utype);
                if str.is_null() {
                    raise(ERR_R_ASN1_LIB, "asn1_ex_c2i");
                    return false;
                }
                // SAFETY: the slot.
                unsafe { pval.write(str.cast()) };
            } else {
                // SAFETY: a live string.
                unsafe { (*str).type_ = utype };
            }
            if content.block.is_null() {
                // SAFETY: a live string.
                if unsafe { string::set(str, cont.as_ptr().cast(), ilen) } == 0 {
                    raise(ERR_R_ASN1_LIB, "asn1_ex_c2i");
                    // SAFETY: as above.
                    unsafe { string::ASN1_STRING_free(str) };
                    // SAFETY: the slot.
                    unsafe { pval.write(ptr::null_mut()) };
                    return false;
                }
            } else {
                // SAFETY: a live string, given the collected block.
                unsafe { string::ASN1_STRING_set0(str, content.block.cast(), ilen) };
                content.block = ptr::null_mut();
            }
            true
        }
    }
}

/// The string in `*pval`, or a new one of type `kind` there.
///
/// # Safety
/// `pval` is a slot holding NULL or a live string.
unsafe fn string_slot(pval: Pval, kind: c_int) -> Option<*mut ASN1_STRING> {
    // SAFETY: the caller's guarantee.
    let str: *mut ASN1_STRING = unsafe { pval.read() }.cast();
    if !str.is_null() {
        return Some(str);
    }
    let str = string::type_new(kind);
    if str.is_null() {
        return None;
    }
    // SAFETY: the slot.
    unsafe { pval.write(str.cast()) };
    Some(str)
}

/// `asn1_find_end`: moves `input` (positioned after an indefinite-length header) past the
/// matching end-of-contents octets.
fn find_end(input: &mut &[u8], inf: bool) -> Result<(), ()> {
    if !inf {
        return Ok(());
    }
    let mut expected_eoc: u32 = 1;
    let mut p = *input;
    while !p.is_empty() {
        if content::is_eoc(p) {
            p = p.get(2..).unwrap_or(&[]);
            expected_eoc = expected_eoc.wrapping_sub(1);
            if expected_eoc == 0 {
                break;
            }
            continue;
        }
        // SAFETY: no cache.
        let Ok(Check::Found(h)) = (unsafe { check_tlen(&mut p, -1, 0, false, ptr::null_mut()) })
        else {
            raise(ERR_R_NESTED_ASN1_ERROR, "asn1_find_end");
            return Err(());
        };
        if h.inf {
            if expected_eoc == u32::MAX {
                raise(ERR_R_NESTED_ASN1_ERROR, "asn1_find_end");
                return Err(());
            }
            expected_eoc = expected_eoc.wrapping_add(1);
        } else {
            p = p.get(h.len..).unwrap_or(&[]);
        }
    }
    if expected_eoc != 0 {
        raise(ASN1_R_MISSING_EOC, "asn1_find_end");
        return Err(());
    }
    *input = p;
    Ok(())
}

/// `asn1_collect`: appends the octets of a constructed string's primitive pieces (universal
/// class, any tag) to `buf`, moving `input` past them (and past the end-of-contents octets if
/// `inf`).
fn collect(buf: &mut Vec<u8>, input: &mut &[u8], inf: bool, depth: c_int) -> Result<(), ()> {
    let mut inf = inf;
    let mut p = *input;
    while !p.is_empty() {
        if content::is_eoc(p) {
            if !inf {
                raise(ASN1_R_UNEXPECTED_EOC, "asn1_collect");
                return Err(());
            }
            p = p.get(2..).unwrap_or(&[]);
            inf = false;
            break;
        }
        // SAFETY: no cache.
        let Ok(Check::Found(h)) =
            (unsafe { check_tlen(&mut p, -1, V_ASN1_UNIVERSAL, false, ptr::null_mut()) })
        else {
            raise(ERR_R_NESTED_ASN1_ERROR, "asn1_collect");
            return Err(());
        };
        if h.cst {
            if depth >= MAX_STRING_NEST {
                raise(ASN1_R_NESTED_ASN1_STRING, "asn1_collect");
                return Err(());
            }
            let mut c = p.get(..h.len).unwrap_or(p);
            collect(buf, &mut c, h.inf, depth.wrapping_add(1))?;
            advance(&mut p, c);
        } else {
            buf.extend_from_slice(p.get(..h.len).unwrap_or(&[]));
            p = p.get(h.len..).unwrap_or(&[]);
        }
    }
    if inf {
        raise(ASN1_R_MISSING_EOC, "asn1_collect");
        return Err(());
    }
    *input = p;
    Ok(())
}

/// The input `*in` and `len` describe, as a slice; `None` (after raising an error) for NULL or
/// a length no buffer can have. A length of 0 or less is an empty slice.
///
/// # Safety
/// `in_` is NULL or valid for reads, and `*in` is NULL or valid for reads of `len` octets.
unsafe fn input_slice<'a>(in_: *mut *const c_uchar, len: c_long) -> Option<&'a [u8]> {
    if len <= 0 {
        return Some(&[]);
    }
    let start = if in_.is_null() {
        ptr::null()
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { in_.read() }
    };
    if start.is_null() {
        raise(ERR_R_PASSED_NULL_PARAMETER, "ASN1_item_ex_d2i");
        return None;
    }
    match usize::try_from(len)
        .ok()
        .filter(|&n| isize::try_from(n).is_ok())
    {
        // SAFETY: the caller's guarantee.
        Some(n) => Some(unsafe { core::slice::from_raw_parts(start, n) }),
        None => {
            raise(ASN1_R_TOO_LONG, "ASN1_item_ex_d2i");
            None
        }
    }
}

/// `asn1_item_ex_d2i_intern`: decodes from `*in`, moving it on; frees `*pval` on failure.
///
/// # Safety
/// As for `ASN1_item_ex_d2i`.
#[expect(clippy::too_many_arguments, reason = "OpenSSL's signature")]
unsafe fn ex_d2i_intern(
    pval: Pval,
    in_: *mut *const c_uchar,
    len: c_long,
    it: *const ASN1_ITEM,
    tag: c_int,
    aclass: c_int,
    opt: bool,
    ctx: Ctx,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> c_int {
    if pval.is_null() || it.is_null() {
        raise(ERR_R_PASSED_NULL_PARAMETER, "asn1_item_ex_d2i_intern");
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let Some(whole) = (unsafe { input_slice(in_, len) }) else {
        // SAFETY: as above.
        unsafe { ASN1_item_ex_free(pval, it) };
        return 0;
    };
    let mut p = whole;
    // SAFETY: as above.
    let rv = unsafe { embed_d2i(pval, &mut p, it, tag, aclass, opt, ctx, 0, libctx, propq) };
    if rv > 0 {
        // SAFETY: as above; `in_` isn't NULL for a non-empty input.
        unsafe { in_.write(whole.as_ptr().wrapping_add(consumed(whole, p).len())) };
    } else {
        // SAFETY: as above.
        unsafe { ASN1_item_ex_free(pval, it) };
    }
    rv
}

ffi_export! {
    /// Decodes a value of `it` from `len` octets at `*in` into `*pval` (an existing value is
    /// reused where it can be; NULL makes one), moving `*in` past it. `tag` and `aclass` give
    /// an implicit tag (-1 for none), `opt` allows the value to be absent (-1), and `ctx` is
    /// NULL or the header cache an item function was given. Returns 1, -1, or 0 on error, when
    /// `*pval` is freed.
    ///
    /// Unlike OpenSSL, a NULL `in` or `*in` with a positive length is an error rather than a
    /// crash (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `pval` is NULL or a slot for a value of `it`, a live item whose tables and functions can
    /// be trusted; `*in` is valid for reads of `len` octets; `ctx` is NULL or a cache from
    /// rustyssl.
    pub unsafe extern "C" fn ASN1_item_ex_d2i(pval: *mut *mut ASN1_VALUE, in_: *mut *const c_uchar, len: c_long, it: *const ASN1_ITEM, tag: c_int, aclass: c_int, opt: c_char, ctx: *mut ASN1_TLC) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ex_d2i_intern(pval, in_, len, it, tag, aclass, opt != 0, ctx.cast(), ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// `ASN1_item_d2i`, passing `libctx` and `propq` to extern items that take them.
    ///
    /// # Safety
    /// As for `ASN1_item_d2i`; `propq` is NULL or a string.
    pub unsafe extern "C" fn ASN1_item_d2i_ex(pval: *mut *mut ASN1_VALUE, in_: *mut *const c_uchar, len: c_long, it: *const ASN1_ITEM, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut ASN1_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        let mut tmp: *mut ASN1_VALUE = ptr::null_mut();
        let pval = if pval.is_null() { &raw mut tmp } else { pval };
        let mut c = Tlc::new();
        // SAFETY: the caller's guarantee, with a local cache.
        if unsafe { ex_d2i_intern(pval, in_, len, it, -1, 0, false, &raw mut c, libctx, propq) } > 0 {
            // SAFETY: the slot just filled.
            unsafe { pval.read() }
        } else {
            ptr::null_mut()
        }
    }
}

ffi_export! {
    /// Decodes a value of `it` (DER or BER) from `len` octets at `*in`, moving `*in` past it.
    /// With `pval` not NULL, decodes into `*pval` (reusing it, or making one if it's NULL) and
    /// stores the result there; on failure `*pval` is freed. Returns the value or NULL.
    ///
    /// # Safety
    /// `pval` is NULL or a slot for a value of `it`, a live item whose tables and functions can
    /// be trusted; `*in` is valid for reads of `len` octets.
    pub unsafe extern "C" fn ASN1_item_d2i(pval: *mut *mut ASN1_VALUE, in_: *mut *const c_uchar, len: c_long, it: *const ASN1_ITEM) -> *mut ASN1_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_d2i_ex(pval, in_, len, it, ptr::null_mut(), ptr::null()) }
    }
}

#[cfg(test)]
mod tests {
    use rustyssl_abi::{ASN1_ITYPE_EXTERN, ASN1_TLC};

    use super::*;
    use crate::asn1::tpl::items::ASN1_OCTET_STRING_it;
    use crate::asn1::tpl::{Item, item};

    #[test]
    fn null_input_is_an_error() {
        // SAFETY: no preconditions.
        let it = unsafe { ASN1_OCTET_STRING_it() };
        // SAFETY: NULL input is refused.
        let v = unsafe { ASN1_item_d2i(ptr::null_mut(), ptr::null_mut(), 5, it) };
        assert!(v.is_null());
        let mut p: *const c_uchar = ptr::null();
        // SAFETY: as above.
        let v = unsafe { ASN1_item_d2i(ptr::null_mut(), &raw mut p, 5, it) };
        assert!(v.is_null());
        // SAFETY: no preconditions.
        unsafe { err::ERR_clear_error() };
    }

    /// An extern item's decoder that claims one octet more than it was given.
    unsafe extern "C" fn overreach(
        _pval: *mut *mut ASN1_VALUE,
        input: *mut *const c_uchar,
        len: c_long,
        _it: *const ASN1_ITEM,
        _tag: c_int,
        _aclass: c_int,
        _opt: c_char,
        _ctx: *mut ASN1_TLC,
    ) -> c_int {
        // SAFETY: the engine's input pointer.
        let start = unsafe { input.read() };
        // SAFETY: as above; moved, never read through.
        unsafe { input.write(start.wrapping_add(usize::try_from(len).unwrap() + 1)) };
        1
    }

    struct Funcs(ASN1_EXTERN_FUNCS);
    // SAFETY: immutable, with no pointers but the function.
    unsafe impl Sync for Funcs {}

    static OVERREACH_FUNCS: Funcs = Funcs(ASN1_EXTERN_FUNCS {
        app_data: ptr::null_mut(),
        asn1_ex_new: None,
        asn1_ex_free: None,
        asn1_ex_clear: None,
        asn1_ex_d2i: Some(overreach),
        asn1_ex_i2d: None,
        asn1_ex_print: None,
        asn1_ex_new_ex: None,
        asn1_ex_d2i_ex: None,
    });
    static OVERREACH: Item = item(
        ASN1_ITYPE_EXTERN,
        0,
        ptr::null(),
        0,
        (&raw const OVERREACH_FUNCS.0).cast(),
        0,
        c"OVERREACH",
    );

    #[test]
    fn an_item_reading_past_its_input_is_refused() {
        let input = [0x04u8, 0x00];
        let mut p = input.as_ptr();
        // SAFETY: the input holds 2 octets.
        let v = unsafe { ASN1_item_d2i(ptr::null_mut(), &raw mut p, 2, &raw const OVERREACH.0) };
        assert!(v.is_null());
        assert_eq!(p, input.as_ptr());
        // SAFETY: no preconditions.
        unsafe { err::ERR_clear_error() };
    }
}
