//! Printing values by their items (`ASN1_item_print(3)`) and the print context (`ASN1_PCTX_new`
//! and its flag accessors), as OpenSSL's `tasn_prn.c` does: one line per field, named by field
//! and type as the context's flags say, primitives rendered by type (INTEGERs in decimal or
//! hex, times, OIDs with their names, strings with `ASN1_STRING_print_ex`, octet and bit
//! strings dumped, SEQUENCEs held whole listed with `ASN1_parse_dump`).
//!
//! Formatted output goes through `BIO_printf` with OpenSSL's own format strings, so widths
//! and padding come out the same.

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_AFLG_CONST_CB, ASN1_AUX, ASN1_EXTERN_FUNCS, ASN1_ITEM, ASN1_ITYPE_CHOICE,
    ASN1_ITYPE_EXTERN, ASN1_ITYPE_MSTRING, ASN1_ITYPE_NDEF_SEQUENCE, ASN1_ITYPE_PRIMITIVE,
    ASN1_ITYPE_SEQUENCE, ASN1_OBJECT, ASN1_OP_PRINT_POST, ASN1_OP_PRINT_PRE, ASN1_PCTX,
    ASN1_PCTX_FLAGS_NO_ANY_TYPE, ASN1_PCTX_FLAGS_NO_FIELD_NAME, ASN1_PCTX_FLAGS_NO_STRUCT_NAME,
    ASN1_PCTX_FLAGS_SHOW_ABSENT, ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME,
    ASN1_PCTX_FLAGS_SHOW_SEQUENCE, ASN1_PCTX_FLAGS_SHOW_SSOF, ASN1_PCTX_FLAGS_SHOW_TYPE,
    ASN1_PRIMITIVE_FUNCS, ASN1_PRINT_ARG, ASN1_STRING, ASN1_TEMPLATE, ASN1_TFLG_EMBED,
    ASN1_TFLG_SET_OF, ASN1_TFLG_SK_MASK, ASN1_TYPE, ASN1_VALUE, BIO, ERR_LIB_ASN1, OPENSSL_STACK,
    V_ASN1_ANY, V_ASN1_BIT_STRING, V_ASN1_BOOLEAN, V_ASN1_ENUMERATED, V_ASN1_GENERALIZEDTIME,
    V_ASN1_INTEGER, V_ASN1_NEG, V_ASN1_NULL, V_ASN1_OBJECT, V_ASN1_OCTET_STRING, V_ASN1_OTHER,
    V_ASN1_SEQUENCE, V_ASN1_SET, V_ASN1_UTCTIME,
};

use super::{choice_selector, field_ptr, itype, long_to_int, template_flags, template_item, utype};
use crate::asn1::parse::ASN1_parse_dump;
use crate::asn1::text::{ASN1_STRING_print_ex, ASN1_tag2str};
use crate::asn1::time::{ASN1_GENERALIZEDTIME_print, ASN1_UTCTIME_print};
use crate::bio;
use crate::bio::print::BIO_printf;
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects;
use crate::stack;
use crate::x509v3::i2s_ASN1_INTEGER;

/// A print context, laid out as OpenSSL's private `asn1_pctx_st`.
#[repr(C)]
pub(crate) struct Pctx {
    flags: c_ulong,
    nm_flags: c_ulong,
    cert_flags: c_ulong,
    oid_flags: c_ulong,
    str_flags: c_ulong,
}

/// The context `ASN1_item_print` uses for NULL: absent fields shown.
static DEFAULT_PCTX: Pctx = Pctx {
    flags: ASN1_PCTX_FLAGS_SHOW_ABSENT.cast_unsigned() as c_ulong,
    nm_flags: 0,
    cert_flags: 0,
    oid_flags: 0,
    str_flags: 0,
};

/// Whether the context has `flag`.
fn has(pctx: &Pctx, flag: c_int) -> bool {
    pctx.flags & c_ulong::from(flag.cast_unsigned()) != 0
}

/// A value's slot for reading: `const ASN1_VALUE **`.
type Cpval = *mut *const ASN1_VALUE;

/// `BIO_puts`.
///
/// # Safety
/// `out` is NULL or a live BIO; `s` is a string.
unsafe fn puts(out: *mut BIO, s: *const c_char) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { bio::BIO_puts(out, s) }
}

/// `asn1_print_fsname`: the indent, then the field and type names (as the context allows) and
/// `": "`.
///
/// # Safety
/// `out` is NULL or a live BIO; `fname` and `sname` are NULL or strings.
unsafe fn print_fsname(
    out: *mut BIO,
    indent: c_int,
    fname: *const c_char,
    sname: *const c_char,
    pctx: &Pctx,
) -> c_int {
    const SPACES: &[u8; 20] = b"                    ";
    let mut indent = indent;
    while indent > 20 {
        // SAFETY: the caller's BIO; 20 octets.
        if unsafe { bio::BIO_write(out, SPACES.as_ptr().cast(), 20) } != 20 {
            return 0;
        }
        indent = indent.wrapping_sub(20);
    }
    // SAFETY: as above; at most 20 octets (a negative count writes nothing).
    if unsafe { bio::BIO_write(out, SPACES.as_ptr().cast(), indent) } != indent {
        return 0;
    }
    let sname = if has(pctx, ASN1_PCTX_FLAGS_NO_STRUCT_NAME) {
        ptr::null()
    } else {
        sname
    };
    let fname = if has(pctx, ASN1_PCTX_FLAGS_NO_FIELD_NAME) {
        ptr::null()
    } else {
        fname
    };
    if sname.is_null() && fname.is_null() {
        return 1;
    }
    // SAFETY: as above.
    if !fname.is_null() && unsafe { puts(out, fname) } <= 0 {
        return 0;
    }
    if !sname.is_null() {
        let r = if fname.is_null() {
            // SAFETY: as above.
            unsafe { puts(out, sname) }
        } else {
            // SAFETY: as above; the format takes one string.
            unsafe { BIO_printf(out, c" (%s)".as_ptr(), sname) }
        };
        if r <= 0 {
            return 0;
        }
    }
    // SAFETY: as above.
    if unsafe { bio::BIO_write(out, c": ".as_ptr().cast(), 2) } != 2 {
        return 0;
    }
    1
}

/// An aux callback, picked as `asn1_item_print_ctx` picks it.
#[derive(Clone, Copy)]
enum Callback {
    Const(
        unsafe extern "C" fn(c_int, *mut *const ASN1_VALUE, *const ASN1_ITEM, *mut c_void) -> c_int,
    ),
    Mut(unsafe extern "C" fn(c_int, *mut *mut ASN1_VALUE, *const ASN1_ITEM, *mut c_void) -> c_int),
}

impl Callback {
    /// Calls it for `op` with the print arguments.
    ///
    /// # Safety
    /// The application's callback, with a live value of `it`.
    unsafe fn call(
        self,
        op: c_int,
        fld: Cpval,
        it: *const ASN1_ITEM,
        parg: *mut ASN1_PRINT_ARG,
    ) -> c_int {
        match self {
            // SAFETY: the caller's guarantee.
            Self::Const(cb) => unsafe { cb(op, fld, it, parg.cast()) },
            // SAFETY: as above.
            Self::Mut(cb) => unsafe { cb(op, fld.cast(), it, parg.cast()) },
        }
    }
}

/// `asn1_item_print_ctx`.
///
/// # Safety
/// `out` is NULL or a live BIO; `fld` holds NULL or a live value of `it` (a BOOLEAN's slot is
/// its `int`), a live item whose tables and functions can be trusted; `fname` and `sname` are
/// NULL or strings.
#[expect(clippy::too_many_arguments, reason = "OpenSSL's signature")]
unsafe fn item_print(
    out: *mut BIO,
    fld: Cpval,
    indent: c_int,
    it: *const ASN1_ITEM,
    fname: *const c_char,
    sname: *const c_char,
    nohdr: bool,
    pctx: &Pctx,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let item = unsafe { &*it };
    // SAFETY: as above.
    let (kind, item_utype) = (unsafe { itype(it) }, unsafe { utype(it) });
    // SAFETY: as above.
    let absent = unsafe { fld.read() }.is_null();
    if (kind != ASN1_ITYPE_PRIMITIVE || item_utype != V_ASN1_BOOLEAN) && absent {
        if has(pctx, ASN1_PCTX_FLAGS_SHOW_ABSENT) {
            // SAFETY: as above.
            if !nohdr && unsafe { print_fsname(out, indent, fname, sname, pctx) } == 0 {
                return 0;
            }
            // SAFETY: as above.
            if unsafe { puts(out, c"<ABSENT>\n".as_ptr()) } <= 0 {
                return 0;
            }
        }
        return 1;
    }
    match kind {
        ASN1_ITYPE_PRIMITIVE if !item.templates.is_null() => {
            // SAFETY: the item's template.
            if unsafe { template_print(out, fld, indent, item.templates, pctx) } == 0 {
                return 0;
            }
        }
        ASN1_ITYPE_PRIMITIVE | ASN1_ITYPE_MSTRING => {
            // SAFETY: as above.
            if unsafe { primitive_print(out, fld, it, indent, fname, sname, pctx) } == 0 {
                return 0;
            }
        }
        ASN1_ITYPE_EXTERN => {
            // SAFETY: as above.
            if !nohdr && unsafe { print_fsname(out, indent, fname, sname, pctx) } == 0 {
                return 0;
            }
            // SAFETY: an extern item's funcs.
            let ef = unsafe { super::funcs::<ASN1_EXTERN_FUNCS>(it) };
            if let Some(print) = ef.and_then(|ef| ef.asn1_ex_print) {
                // SAFETY: the item's own function.
                let i = unsafe { print(out, fld, indent, c"".as_ptr(), pctx_ptr(pctx)) };
                if i == 0 {
                    return 0;
                }
                // SAFETY: as above.
                if i == 2 && unsafe { puts(out, c"\n".as_ptr()) } <= 0 {
                    return 0;
                }
                return 1;
            }
            if !sname.is_null() {
                // SAFETY: as above; the format takes one string.
                let r = unsafe { BIO_printf(out, c":EXTERNAL TYPE %s\n".as_ptr(), sname) };
                if r <= 0 {
                    return 0;
                }
            }
        }
        ASN1_ITYPE_CHOICE => {
            // SAFETY: a live CHOICE structure.
            let i = unsafe { choice_selector(fld.cast(), it) };
            let Ok(index) = usize::try_from(i) else {
                return selector_error(out, i);
            };
            if c_long::from(i) >= item.tcount {
                return selector_error(out, i);
            }
            let tt = item.templates.wrapping_add(index);
            // SAFETY: a template of the item, for a field of the structure.
            let tmpfld = unsafe { field_ptr(fld.cast(), tt) };
            // SAFETY: as above.
            if unsafe { template_print(out, tmpfld.cast(), indent, tt, pctx) } == 0 {
                return 0;
            }
        }
        ASN1_ITYPE_SEQUENCE | ASN1_ITYPE_NDEF_SEQUENCE => {
            // SAFETY: as above.
            if !nohdr && unsafe { print_fsname(out, indent, fname, sname, pctx) } == 0 {
                return 0;
            }
            if !fname.is_null() || !sname.is_null() {
                let text = if has(pctx, ASN1_PCTX_FLAGS_SHOW_SEQUENCE) {
                    c" {\n"
                } else {
                    c"\n"
                };
                // SAFETY: as above.
                if unsafe { puts(out, text.as_ptr()) } <= 0 {
                    return 0;
                }
            }
            let aux: *const ASN1_AUX = item.funcs.cast();
            let callback = if aux.is_null() {
                None
            } else {
                // SAFETY: a SEQUENCE's funcs are its aux data.
                let aux = unsafe { &*aux };
                if aux.flags & ASN1_AFLG_CONST_CB != 0 {
                    aux.asn1_const_cb.map(Callback::Const)
                } else {
                    aux.asn1_cb.map(Callback::Mut)
                }
            };
            let mut parg = ASN1_PRINT_ARG {
                out,
                indent,
                pctx: pctx_ptr(pctx),
            };
            if let Some(cb) = callback {
                // SAFETY: the application's callback.
                let i = unsafe { cb.call(ASN1_OP_PRINT_PRE, fld, it, &raw mut parg) };
                if i == 0 {
                    return 0;
                }
                if i == 2 {
                    return 1;
                }
            }
            let count = usize::try_from(item.tcount).unwrap_or(0);
            for i in 0..count {
                let tt = item.templates.wrapping_add(i);
                // SAFETY: the structure.
                let structure = unsafe { fld.read() };
                // SAFETY: as above, and a template of the item.
                let seqtt = unsafe { super::do_adb(structure, tt, true) };
                if seqtt.is_null() {
                    return 0;
                }
                // SAFETY: as above.
                let tmpfld = unsafe { field_ptr(fld.cast(), seqtt) };
                // SAFETY: as above.
                if unsafe {
                    template_print(out, tmpfld.cast(), indent.wrapping_add(2), seqtt, pctx)
                } == 0
                {
                    return 0;
                }
            }
            if has(pctx, ASN1_PCTX_FLAGS_SHOW_SEQUENCE) {
                // SAFETY: as above; the format takes a width and a string.
                let r = unsafe { BIO_printf(out, c"%*s}\n".as_ptr(), indent, c"".as_ptr()) };
                if r < 0 {
                    return 0;
                }
            }
            if let Some(cb) = callback {
                // SAFETY: as above.
                if unsafe { cb.call(ASN1_OP_PRINT_POST, fld, it, &raw mut parg) } == 0 {
                    return 0;
                }
            }
        }
        _ => {
            // SAFETY: as above; the format takes an int.
            unsafe { BIO_printf(out, c"Unprocessed type %d\n".as_ptr(), kind) };
            return 0;
        }
    }
    1
}

/// The line for a CHOICE selector out of range.
fn selector_error(out: *mut BIO, i: c_int) -> c_int {
    // SAFETY: the caller's BIO; the format takes an int.
    c_int::from(unsafe { BIO_printf(out, c"ERROR: selector [%d] invalid\n".as_ptr(), i) } > 0)
}

/// The context as the `ASN1_PCTX *` item functions and callbacks get.
fn pctx_ptr(pctx: &Pctx) -> *const ASN1_PCTX {
    ptr::from_ref(pctx).cast()
}

/// `asn1_template_print_ctx`.
///
/// # Safety
/// As for [`item_print`], with `fld` the field's slot (or the field, if embedded) and `tt` a
/// live template.
unsafe fn template_print(
    out: *mut BIO,
    fld: Cpval,
    indent: c_int,
    tt: *const ASN1_TEMPLATE,
    pctx: &Pctx,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let flags = unsafe { template_flags(tt) };
    // SAFETY: as above.
    let it = unsafe { template_item(tt) };
    let sname = if has(pctx, ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME) {
        // SAFETY: a live item.
        unsafe { (*it).sname }
    } else {
        ptr::null()
    };
    // SAFETY: a live template.
    let field_name = unsafe { (*tt).field_name };
    let fname = if has(pctx, ASN1_PCTX_FLAGS_NO_FIELD_NAME) {
        ptr::null()
    } else {
        field_name
    };
    let mut tfld: *const ASN1_VALUE = fld.cast_const().cast();
    let fld = if flags & ASN1_TFLG_EMBED != 0 {
        &raw mut tfld
    } else {
        fld
    };
    if flags & ASN1_TFLG_SK_MASK == 0 {
        // SAFETY: the caller's guarantee.
        return unsafe { item_print(out, fld, indent, it, fname, sname, false, pctx) };
    }
    if !fname.is_null() {
        let r = if has(pctx, ASN1_PCTX_FLAGS_SHOW_SSOF) {
            let tname = if flags & ASN1_TFLG_SET_OF != 0 {
                c"SET"
            } else {
                c"SEQUENCE"
            };
            // SAFETY: the caller's BIO; the format takes a width and three strings.
            unsafe {
                BIO_printf(
                    out,
                    c"%*s%s OF %s {\n".as_ptr(),
                    indent,
                    c"".as_ptr(),
                    tname.as_ptr(),
                    field_name,
                )
            }
        } else {
            // SAFETY: as above; a width and two strings.
            unsafe { BIO_printf(out, c"%*s%s:\n".as_ptr(), indent, c"".as_ptr(), fname) }
        };
        if r <= 0 {
            return 0;
        }
    }
    // SAFETY: the field's slot holds a stack, or NULL.
    let stack: *mut OPENSSL_STACK = unsafe { fld.read() }.cast_mut().cast();
    let mut i: c_int = 0;
    // SAFETY: a live stack, or NULL (-1).
    while i < unsafe { stack::OPENSSL_sk_num(stack) } {
        // SAFETY: the caller's BIO.
        if i > 0 && unsafe { puts(out, c"\n".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: as above.
        let mut skitem: *const ASN1_VALUE = unsafe { stack::OPENSSL_sk_value(stack, i) }
            .cast_const()
            .cast();
        // SAFETY: an element, a value of the item.
        if unsafe {
            item_print(
                out,
                &raw mut skitem,
                indent.wrapping_add(2),
                it,
                ptr::null(),
                ptr::null(),
                true,
                pctx,
            )
        } == 0
        {
            return 0;
        }
        i = i.wrapping_add(1);
    }
    if i == 0 {
        let what = if stack.is_null() { c"ABSENT" } else { c"EMPTY" };
        // SAFETY: as above; a width and two strings.
        if unsafe {
            BIO_printf(
                out,
                c"%*s<%s>\n".as_ptr(),
                indent.wrapping_add(2),
                c"".as_ptr(),
                what.as_ptr(),
            )
        } <= 0
        {
            return 0;
        }
    }
    if has(pctx, ASN1_PCTX_FLAGS_SHOW_SEQUENCE) {
        // SAFETY: as above; a width and a string.
        let r = unsafe { BIO_printf(out, c"%*s}\n".as_ptr(), indent, c"".as_ptr()) };
        if r <= 0 {
            return 0;
        }
    }
    1
}

/// `asn1_print_boolean`.
///
/// # Safety
/// `out` is NULL or a live BIO.
unsafe fn print_boolean(out: *mut BIO, boolval: c_int) -> c_int {
    let s = match boolval {
        -1 => c"BOOL ABSENT",
        0 => c"FALSE",
        _ => c"TRUE",
    };
    // SAFETY: the caller's BIO.
    c_int::from(unsafe { puts(out, s.as_ptr()) } > 0)
}

/// `asn1_print_integer`: through `i2s_ASN1_INTEGER`, so an ENUMERATED (not an INTEGER to it)
/// fails, as in OpenSSL.
///
/// # Safety
/// `out` is NULL or a live BIO; `str` is NULL or a live string.
unsafe fn print_integer(out: *mut BIO, str: *const ASN1_STRING) -> c_int {
    // SAFETY: the caller's guarantee.
    let s = unsafe { i2s_ASN1_INTEGER(ptr::null_mut(), str) };
    if s.is_null() {
        return 0;
    }
    // SAFETY: as above; a string.
    let ret = c_int::from(unsafe { puts(out, s) } > 0);
    // SAFETY: the string, from this allocator.
    unsafe { mem::release(s.cast()) };
    ret
}

/// `asn1_print_oid`: the long name (or nothing) and the dotted form, which OpenSSL cuts to 79
/// characters.
///
/// # Safety
/// `out` is NULL or a live BIO; `oid` is a live object.
unsafe fn print_oid(out: *mut BIO, oid: *const ASN1_OBJECT) -> c_int {
    let mut objbuf = [0 as c_char; 80];
    // SAFETY: a live object.
    let nid = unsafe { objects::OBJ_obj2nid(oid.cast()) };
    // SAFETY: no preconditions.
    let ln = unsafe { objects::OBJ_nid2ln(nid) };
    let ln = if ln.is_null() { c"".as_ptr() } else { ln };
    // SAFETY: a buffer of 80; a live object.
    unsafe { objects::OBJ_obj2txt(objbuf.as_mut_ptr(), 80, oid.cast(), 1) };
    // SAFETY: the caller's BIO; two strings.
    c_int::from(unsafe { BIO_printf(out, c"%s (%s)".as_ptr(), ln, objbuf.as_ptr()) } > 0)
}

/// `asn1_print_obstring`: a BIT STRING's unused bits, then the octets dumped.
///
/// # Safety
/// `out` is NULL or a live BIO; `str` is a live string.
unsafe fn print_obstring(out: *mut BIO, str: *const ASN1_STRING, indent: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let s = unsafe { &*str };
    let r = if s.type_ == V_ASN1_BIT_STRING {
        // SAFETY: the caller's BIO; the format takes a long.
        unsafe { BIO_printf(out, c" (%ld unused bits)\n".as_ptr(), s.flags & 0x7) }
    } else {
        // SAFETY: as above.
        unsafe { puts(out, c"\n".as_ptr()) }
    };
    if r <= 0 {
        return 0;
    }
    let dump = || {
        // SAFETY: as above; the string's data holds its length.
        unsafe { bio::dump::BIO_dump_indent(out, s.data.cast(), s.length, indent.wrapping_add(2)) }
    };
    if s.length > 0 && dump() <= 0 {
        return 0;
    }
    1
}

/// `asn1_primitive_print`.
///
/// # Safety
/// As for [`item_print`], for a primitive or MSTRING item.
unsafe fn primitive_print(
    out: *mut BIO,
    fld: Cpval,
    it: *const ASN1_ITEM,
    indent: c_int,
    fname: *const c_char,
    sname: *const c_char,
    pctx: &Pctx,
) -> c_int {
    // SAFETY: the caller's guarantee.
    if unsafe { print_fsname(out, indent, fname, sname, pctx) } == 0 {
        return 0;
    }
    // SAFETY: a primitive item's funcs.
    let pf = unsafe { super::funcs::<ASN1_PRIMITIVE_FUNCS>(it) };
    if let Some(print) = pf.and_then(|pf| pf.prim_print) {
        // SAFETY: the item's own function.
        return unsafe { print(out, fld, it, indent, pctx_ptr(pctx)) };
    }
    // SAFETY: the caller's guarantee.
    let item_size = unsafe { (*it).size };
    let mut fld = fld;
    let (mut kind, mut str): (c_int, *const ASN1_STRING) = {
        // SAFETY: as above.
        if unsafe { itype(it) } == ASN1_ITYPE_MSTRING {
            // SAFETY: an MSTRING's value is a string.
            let s: *const ASN1_STRING = unsafe { fld.read() }.cast();
            // SAFETY: as above.
            (unsafe { (*s).type_ } & !V_ASN1_NEG, s)
        } else {
            // SAFETY: as above.
            let u = unsafe { utype(it) };
            let s = if u == V_ASN1_BOOLEAN {
                ptr::null()
            } else {
                // SAFETY: as above.
                unsafe { fld.read() }.cast()
            };
            (u, s)
        }
    };
    let pname = if kind == V_ASN1_ANY {
        // SAFETY: an ANY's value is an ASN1_TYPE.
        let atype: *const ASN1_TYPE = unsafe { fld.read() }.cast();
        // SAFETY: as above.
        kind = unsafe { (*atype).type_ };
        // SAFETY: its value's slot, the union.
        fld = unsafe { (&raw const (*atype).value).cast_mut().cast() };
        // SAFETY: as above.
        str = unsafe { fld.read() }.cast();
        if has(pctx, ASN1_PCTX_FLAGS_NO_ANY_TYPE) {
            ptr::null()
        } else {
            tag_name(kind)
        }
    } else if has(pctx, ASN1_PCTX_FLAGS_SHOW_TYPE) {
        tag_name(kind)
    } else {
        ptr::null()
    };
    if kind == V_ASN1_NULL {
        // SAFETY: the caller's BIO.
        return c_int::from(unsafe { puts(out, c"NULL\n".as_ptr()) } > 0);
    }
    if !pname.is_null() {
        // SAFETY: as above; a static string.
        if unsafe { puts(out, pname) } <= 0 || unsafe { puts(out, c":".as_ptr()) } <= 0 {
            return 0;
        }
    }
    let mut needlf = true;
    let ret = match kind {
        V_ASN1_BOOLEAN => {
            // SAFETY: a BOOLEAN's slot is its `int`.
            let mut boolval = unsafe { fld.cast::<c_int>().read() };
            if boolval == -1 {
                boolval = long_to_int(item_size);
            }
            // SAFETY: as above.
            unsafe { print_boolean(out, boolval) }
        }
        // SAFETY: as above; a string.
        V_ASN1_INTEGER | V_ASN1_ENUMERATED => unsafe { print_integer(out, str) },
        // SAFETY: as above.
        V_ASN1_UTCTIME => unsafe { ASN1_UTCTIME_print(out, str) },
        // SAFETY: as above.
        V_ASN1_GENERALIZEDTIME => unsafe { ASN1_GENERALIZEDTIME_print(out, str) },
        V_ASN1_OBJECT => {
            // SAFETY: as above.
            let oid = unsafe { fld.read() };
            // SAFETY: an object.
            unsafe { print_oid(out, oid.cast()) }
        }
        V_ASN1_OCTET_STRING | V_ASN1_BIT_STRING => {
            needlf = false;
            // SAFETY: as above.
            unsafe { print_obstring(out, str, indent) }
        }
        V_ASN1_SEQUENCE | V_ASN1_SET | V_ASN1_OTHER => {
            // SAFETY: as above.
            if unsafe { puts(out, c"\n".as_ptr()) } <= 0 {
                return 0;
            }
            needlf = false;
            // SAFETY: as above.
            let held = unsafe { &*str };
            let (data, length) = (held.data, held.length);
            // SAFETY: as above.
            c_int::from(unsafe { ASN1_parse_dump(out, data, c_long::from(length), indent, 0) } > 0)
        }
        // SAFETY: as above.
        _ => unsafe { ASN1_STRING_print_ex(out, str, pctx.str_flags) },
    };
    if ret == 0 {
        return 0;
    }
    // SAFETY: as above.
    if needlf && unsafe { puts(out, c"\n".as_ptr()) } <= 0 {
        return 0;
    }
    1
}

/// `ASN1_tag2str`.
fn tag_name(tag: c_int) -> *const c_char {
    // SAFETY: no preconditions.
    unsafe { ASN1_tag2str(tag) }
}

ffi_export! {
    /// Prints `ifld`, a value of `it`, to `out` at `indent`, as `pctx` says (NULL: absent
    /// fields shown). Returns 1, or 0.
    ///
    /// # Safety
    /// `out` is a live BIO; `ifld` is NULL or a live value of `it`, a live item whose tables and
    /// functions can be trusted; `pctx` is NULL or a live context.
    pub unsafe extern "C" fn ASN1_item_print(out: *mut BIO, ifld: *const ASN1_VALUE, indent: c_int, it: *const ASN1_ITEM, pctx: *const ASN1_PCTX) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        let pctx: &Pctx = if pctx.is_null() {
            &DEFAULT_PCTX
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { &*pctx.cast::<Pctx>() }
        };
        let sname = if has(pctx, ASN1_PCTX_FLAGS_NO_STRUCT_NAME) {
            ptr::null()
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { (*it).sname }
        };
        let mut fld = ifld;
        // SAFETY: as above, with a local slot.
        unsafe { item_print(out, &raw mut fld, indent, it, ptr::null(), sname, false, pctx) }
    }
}

ffi_export! {
    /// A new print context with no flags, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_PCTX_new() -> *mut ASN1_PCTX
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        mem::alloc_zeroed(size_of::<Pctx>()).cast()
    }
}

ffi_export! {
    /// Frees a print context; NULL does nothing.
    ///
    /// # Safety
    /// `p` is NULL or a context from `ASN1_PCTX_new`.
    pub unsafe extern "C" fn ASN1_PCTX_free(p: *mut ASN1_PCTX)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { mem::release(p.cast()) };
    }
}

/// Defines a print context flag's getter and setter.
macro_rules! accessors {
    ($(
        $field:ident: pub unsafe extern "C" fn $get:ident, pub unsafe extern "C" fn $set:ident;
    )*) => {$(
        ffi_export! {
            #[doc = concat!("The context's `", stringify!($field), "` (0 for NULL).")]
            ///
            /// Unlike OpenSSL, NULL doesn't crash (docs/DEVIATIONS.md).
            ///
            /// # Safety
            /// `p` is NULL or a live context.
            pub unsafe extern "C" fn $get(p: *const ASN1_PCTX) -> c_ulong
            where failure = 0, library = ERR_LIB_ASN1
            {
                if p.is_null() {
                    return 0;
                }
                // SAFETY: the caller's guarantee.
                unsafe { (*p.cast::<Pctx>()).$field }
            }
        }

        ffi_export! {
            #[doc = concat!("Sets the context's `", stringify!($field), "` (nothing for NULL).")]
            ///
            /// # Safety
            /// `p` is NULL or a live context.
            pub unsafe extern "C" fn $set(p: *mut ASN1_PCTX, flags: c_ulong)
            where failure = (), library = ERR_LIB_ASN1
            {
                if !p.is_null() {
                    // SAFETY: the caller's guarantee.
                    unsafe { (*p.cast::<Pctx>()).$field = flags };
                }
            }
        }
    )*};
}

accessors! {
    flags: pub unsafe extern "C" fn ASN1_PCTX_get_flags, pub unsafe extern "C" fn ASN1_PCTX_set_flags;
    nm_flags: pub unsafe extern "C" fn ASN1_PCTX_get_nm_flags, pub unsafe extern "C" fn ASN1_PCTX_set_nm_flags;
    cert_flags: pub unsafe extern "C" fn ASN1_PCTX_get_cert_flags, pub unsafe extern "C" fn ASN1_PCTX_set_cert_flags;
    oid_flags: pub unsafe extern "C" fn ASN1_PCTX_get_oid_flags, pub unsafe extern "C" fn ASN1_PCTX_set_oid_flags;
    str_flags: pub unsafe extern "C" fn ASN1_PCTX_get_str_flags, pub unsafe extern "C" fn ASN1_PCTX_set_str_flags;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::tpl::items::ASN1_OCTET_STRING_it;

    #[test]
    fn contexts_and_printing() {
        // SAFETY: NULL contexts are refused.
        assert_eq!(unsafe { ASN1_PCTX_get_flags(ptr::null()) }, 0);
        // SAFETY: as above.
        unsafe { ASN1_PCTX_set_str_flags(ptr::null_mut(), 1) };
        // SAFETY: no preconditions.
        let method = unsafe { bio::mem::BIO_s_mem() };
        // SAFETY: the built-in method.
        let mem = unsafe { bio::BIO_new(method) };
        let s = crate::asn1::string::type_new(V_ASN1_OCTET_STRING);
        // SAFETY: a new string.
        unsafe { crate::asn1::string::set(s, c"hi".as_ptr().cast(), 2) };
        // SAFETY: no preconditions.
        let it = unsafe { ASN1_OCTET_STRING_it() };
        // SAFETY: a memory BIO and a live string of the item.
        let printed = unsafe { ASN1_item_print(mem, s.cast(), 0, it, ptr::null()) };
        assert_eq!(printed, 1);
        let mut out = [0u8; 128];
        // SAFETY: as above, with room for 128 octets.
        let n = unsafe { bio::BIO_read(mem, out.as_mut_ptr().cast(), 128) };
        let text = out.get(..usize::try_from(n).unwrap()).unwrap();
        assert!(text.starts_with(b"ASN1_OCTET_STRING: \n  0000 - 68 69 "));
        assert!(text.ends_with(b" hi\n"));
        // SAFETY: the BIO and string made here.
        unsafe { bio::BIO_free(mem) };
        // SAFETY: as above.
        unsafe { crate::asn1::string::ASN1_STRING_free(s) };
    }
}
