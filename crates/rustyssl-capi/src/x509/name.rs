//! Names (`x_name.c`, `x509name.c`, `x509_obj.c`, and the parts of `x509_cmp.c` and
//! `a_strex.c` that are a name's): `X509_NAME` and `X509_NAME_ENTRY`, their entries, the
//! one-line and `print_ex` forms, comparison, and the hashes of hashed directories.
//!
//! As OpenSSL's, `X509_NAME` is an extern item over its own structure (which the headers keep
//! opaque): its entries in order, each with the number of the RDN it's in (`set`), the DER it
//! was decoded from or last encoded to, and the canonical encoding comparisons and
//! `X509_NAME_hash_ex` use (each value as lowercased UTF-8 with its spaces collapsed, the
//! RDNs concatenated without the outer SEQUENCE). A change through the entry functions marks
//! the name modified, and the next encoding brings both up to date.

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void};
use core::mem::offset_of;
use core::ptr;

use libc::FILE;
use rustyssl_abi::{
    ASN1_EXTERN_FUNCS, ASN1_ITEM, ASN1_ITYPE_EXTERN, ASN1_ITYPE_PRIMITIVE, ASN1_OBJECT, ASN1_PCTX,
    ASN1_STRFLGS_DUMP_ALL, ASN1_STRING, ASN1_TFLG_SEQUENCE_OF, ASN1_TFLG_SET_OF, ASN1_TLC,
    ASN1_VALUE, B_ASN1_BMPSTRING, B_ASN1_IA5STRING, B_ASN1_PRINTABLESTRING, B_ASN1_T61STRING,
    B_ASN1_UNIVERSALSTRING, B_ASN1_UTF8STRING, B_ASN1_VISIBLESTRING, BIO, BIO_NOCLOSE, BUF_MEM,
    ERR_LIB_ASN1, ERR_LIB_X509, ERR_R_ASN1_LIB, ERR_R_BUF_LIB, ERR_R_CRYPTO_LIB,
    ERR_R_NESTED_ASN1_ERROR, ERR_R_OBJ_LIB, ERR_R_PASSED_NULL_PARAMETER, EVP_MD, MBSTRING_FLAG,
    NID_undef, OPENSSL_STACK, OSSL_LIB_CTX, V_ASN1_APP_CHOOSE, V_ASN1_GENERALSTRING,
    V_ASN1_SEQUENCE, V_ASN1_UNDEF, V_ASN1_UTF8STRING, X509_NAME, X509_NAME_ENTRY,
    X509_R_INVALID_FIELD_NAME, X509_R_NAME_TOO_LONG, X509_R_UNKNOWN_NID, XN_FLAG_COMPAT,
    XN_FLAG_DN_REV, XN_FLAG_DUMP_UNKNOWN_FIELDS, XN_FLAG_FN_ALIGN, XN_FLAG_FN_LN, XN_FLAG_FN_MASK,
    XN_FLAG_FN_NONE, XN_FLAG_FN_OID, XN_FLAG_FN_SN, XN_FLAG_SEP_COMMA_PLUS, XN_FLAG_SEP_CPLUS_SPC,
    XN_FLAG_SEP_MASK, XN_FLAG_SEP_MULTILINE, XN_FLAG_SEP_SPLUS_SPC, XN_FLAG_SPC_EQ,
};

use crate::asn1::string::{ASN1_STRING_copy, ASN1_STRING_set};
use crate::asn1::text::{
    ASN1_PRINTABLE_type, ASN1_STRING_set_by_NID, ASN1_STRING_to_UTF8, ASN1_tag2bit,
};
use crate::asn1::tpl::decode::ASN1_item_ex_d2i;
use crate::asn1::tpl::encode::ASN1_item_ex_i2d;
use crate::asn1::tpl::items::{ASN1_OBJECT_it, ASN1_PRINTABLE_it, d2i, i2d, new_free};
use crate::asn1::tpl::statics::{Templates, sequence};
use crate::asn1::tpl::util::ASN1_item_dup;
use crate::asn1::tpl::{Item, Template, item, item_fns, template, template_at};
use crate::buffer::{BUF_MEM_free, BUF_MEM_grow, BUF_MEM_new};
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::objects::{
    ASN1_OBJECT_free, OBJ_cmp, OBJ_dup, OBJ_nid2ln, OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid,
    OBJ_obj2txt, OBJ_txt2obj, i2t_ASN1_OBJECT,
};
use crate::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_free, OPENSSL_sk_insert, OPENSSL_sk_new_null, OPENSSL_sk_num,
    OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_set, OPENSSL_sk_value,
};

/// `X509_NAME_MAX`: the most of a name's DER that's read.
const NAME_MAX: c_long = 1024 * 1024;
/// `NAME_ONELINE_MAX`.
const ONELINE_MAX: c_int = 1024 * 1024;

/// `X509_NAME_ENTRY` (`X509_name_entry_st`).
#[repr(C)]
pub(crate) struct Entry {
    pub(crate) object: *mut ASN1_OBJECT,
    pub(crate) value: *mut ASN1_STRING,
    /// The number of the RDN the entry is in.
    pub(crate) set: c_int,
    /// Unused (OpenSSL's `size`).
    size: c_int,
}

/// `X509_NAME` (`X509_name_st`).
#[repr(C)]
pub(crate) struct Name {
    /// `STACK_OF(X509_NAME_ENTRY)`.
    pub(crate) entries: *mut OPENSSL_STACK,
    /// Changed since `bytes` and `canon_enc` were made.
    pub(crate) modified: c_int,
    /// The DER.
    pub(crate) bytes: *mut BUF_MEM,
    /// The canonical encoding (NULL for a name without entries).
    pub(crate) canon_enc: *mut c_uchar,
    pub(crate) canon_enclen: c_int,
}

static ENTRY_TT: Templates<2> = Templates([
    template_at(0, 0, offset_of!(Entry, object), c"object", ASN1_OBJECT_it),
    template_at(0, 0, offset_of!(Entry, value), c"value", ASN1_PRINTABLE_it),
]);

item_fns! {
    /// AttributeTypeAndValue: SEQUENCE { type OBJECT IDENTIFIER, value ANY (a printable
    /// string) }.
    pub unsafe extern "C" fn X509_NAME_ENTRY_it = sequence::<Entry, 2>(&ENTRY_TT, None, c"X509_NAME_ENTRY");
}

new_free! {
    pub unsafe extern "C" fn X509_NAME_ENTRY_new, pub unsafe extern "C" fn X509_NAME_ENTRY_free(X509_NAME_ENTRY) = X509_NAME_ENTRY_it;
}

i2d! {
    /// Encodes an AttributeTypeAndValue.
    pub unsafe extern "C" fn i2d_X509_NAME_ENTRY(X509_NAME_ENTRY) = X509_NAME_ENTRY_it;
}

d2i! {
    /// Decodes an AttributeTypeAndValue.
    pub unsafe extern "C" fn d2i_X509_NAME_ENTRY(X509_NAME_ENTRY) = X509_NAME_ENTRY_it;
}

ffi_export! {
    /// A copy of the entry, or NULL.
    ///
    /// # Safety
    /// `ne` is NULL or a live entry.
    pub unsafe extern "C" fn X509_NAME_ENTRY_dup(ne: *const X509_NAME_ENTRY) -> *mut X509_NAME_ENTRY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_NAME_ENTRY_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_dup(it, ne.cast_mut().cast()) }.cast()
    }
}

/// `X509_NAME_ENTRIES`: an RDN, a SET OF entries.
static RDN: Template = template(ASN1_TFLG_SET_OF, 0, c"RDNS", X509_NAME_ENTRY_it);

static ENTRIES: Item = item(
    ASN1_ITYPE_PRIMITIVE,
    -1,
    &raw const RDN.0,
    0,
    ptr::null(),
    0,
    c"X509_NAME_ENTRIES",
);

/// `X509_NAME_ENTRIES` (private).
extern "C" fn entries_it() -> *const ASN1_ITEM {
    &raw const ENTRIES.0
}

/// `X509_NAME_INTERNAL`: a SEQUENCE OF RDNs.
static RDNS: Template = template(ASN1_TFLG_SEQUENCE_OF, 0, c"Name", entries_it);

static INTERNAL: Item = item(
    ASN1_ITYPE_PRIMITIVE,
    -1,
    &raw const RDNS.0,
    0,
    ptr::null(),
    0,
    c"X509_NAME_INTERNAL",
);

/// `X509_NAME_INTERNAL` (private).
extern "C" fn internal_it() -> *const ASN1_ITEM {
    &raw const INTERNAL.0
}

/// The extern functions (`x509_name_ff`).
struct Funcs(ASN1_EXTERN_FUNCS);
// SAFETY: immutable, with no pointers but functions.
unsafe impl Sync for Funcs {}

static FUNCS: Funcs = Funcs(ASN1_EXTERN_FUNCS {
    app_data: ptr::null_mut(),
    asn1_ex_new: Some(ex_new),
    asn1_ex_free: Some(ex_free),
    asn1_ex_clear: None,
    asn1_ex_d2i: Some(ex_d2i),
    asn1_ex_i2d: Some(ex_i2d),
    asn1_ex_print: Some(ex_print),
    asn1_ex_new_ex: None,
    asn1_ex_d2i_ex: None,
});

static NAME: Item = item(
    ASN1_ITYPE_EXTERN,
    V_ASN1_SEQUENCE,
    ptr::null(),
    0,
    (&raw const FUNCS.0).cast(),
    0,
    c"X509_NAME",
);

ffi_export! {
    /// Name: a SEQUENCE OF RDNs, each a SET OF AttributeTypeAndValue.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_NAME_it() -> *const ASN1_ITEM
    where failure = ptr::null(), library = ERR_LIB_ASN1
    {
        &raw const NAME.0
    }
}

new_free! {
    pub unsafe extern "C" fn X509_NAME_new, pub unsafe extern "C" fn X509_NAME_free(X509_NAME) = X509_NAME_it;
}

i2d! {
    /// Encodes a name (from the DER it keeps, made again if it's changed).
    pub unsafe extern "C" fn i2d_X509_NAME(X509_NAME) = X509_NAME_it;
}

d2i! {
    /// Decodes a name.
    pub unsafe extern "C" fn d2i_X509_NAME(X509_NAME) = X509_NAME_it;
}

ffi_export! {
    /// A copy of the name, or NULL.
    ///
    /// # Safety
    /// `xn` is NULL or a live name.
    pub unsafe extern "C" fn X509_NAME_dup(xn: *const X509_NAME) -> *mut X509_NAME
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_NAME_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_dup(it, xn.cast_mut().cast()) }.cast()
    }
}

/// The structure behind a pointer.
///
/// # Safety
/// `p` is NULL or a live `X509_NAME`, which nothing else changes while the reference lives.
pub(crate) unsafe fn name_of<'a>(p: *const X509_NAME) -> Option<&'a mut Name> {
    // SAFETY: the caller's guarantee; an `X509_NAME` is a `Name`.
    unsafe { p.cast::<Name>().cast_mut().as_mut() }
}

/// The entry behind a pointer.
///
/// # Safety
/// `p` is NULL or a live `X509_NAME_ENTRY`, which nothing else changes while the reference
/// lives.
pub(crate) unsafe fn entry_of<'a>(p: *const X509_NAME_ENTRY) -> Option<&'a mut Entry> {
    // SAFETY: the caller's guarantee; an `X509_NAME_ENTRY` is an `Entry`.
    unsafe { p.cast::<Entry>().cast_mut().as_mut() }
}

/// The number of items on a stack (0 for NULL).
///
/// # Safety
/// `sk` is NULL or a live stack.
unsafe fn sk_num(sk: *const OPENSSL_STACK) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { OPENSSL_sk_num(sk) }.max(0)
}

/// Item `i` of a stack of entries, or NULL.
///
/// # Safety
/// `sk` is NULL or a live stack of entries.
unsafe fn sk_entry<'a>(sk: *const OPENSSL_STACK, i: c_int) -> Option<&'a mut Entry> {
    // SAFETY: the caller's guarantee.
    let p = unsafe { OPENSSL_sk_value(sk, i) };
    // SAFETY: an entry of the stack, or NULL.
    unsafe { entry_of(p.cast()) }
}

/// `X509_NAME_ENTRY_free` as a stack's free function.
unsafe extern "C" fn free_entry(p: *mut c_void) {
    // SAFETY: an entry of the stack being freed.
    unsafe { X509_NAME_ENTRY_free(p.cast()) };
}

/// `sk_X509_NAME_ENTRY_free` as a stack's free function (for the RDNs, whose entries are
/// another's).
unsafe extern "C" fn free_rdn(p: *mut c_void) {
    // SAFETY: an RDN of the stack being freed.
    unsafe { OPENSSL_sk_free(p.cast()) };
}

/// `sk_X509_NAME_ENTRY_pop_free(.., X509_NAME_ENTRY_free)` as a stack's free function.
unsafe extern "C" fn pop_free_rdn(p: *mut c_void) {
    // SAFETY: an RDN of the stack being freed, its entries its own.
    unsafe { OPENSSL_sk_pop_free(p.cast(), Some(free_entry)) };
}

ffi_callback! {
    /// `x509_name_ex_new`: an empty name, modified.
    ///
    /// # Safety
    /// `val` is writable.
    pub(crate) unsafe extern "C" fn ex_new(val: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        let p: *mut Name = mem::zalloc(size_of::<Name>(), ptr::null(), 0).cast();
        // SAFETY: just made, or NULL.
        let Some(n) = (unsafe { p.as_mut() }) else { return 0 };
        // SAFETY: no preconditions.
        n.entries = unsafe { OPENSSL_sk_new_null() };
        if n.entries.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_CRYPTO_LIB, "x509_name_ex_new");
            // SAFETY: made above.
            unsafe { mem::release(p.cast()) };
            return 0;
        }
        // SAFETY: no preconditions.
        n.bytes = unsafe { BUF_MEM_new() };
        if n.bytes.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_BUF_LIB, "x509_name_ex_new");
            // SAFETY: made above.
            unsafe { OPENSSL_sk_free(n.entries) };
            // SAFETY: as above.
            unsafe { mem::release(p.cast()) };
            return 0;
        }
        n.modified = 1;
        // SAFETY: the caller's slot.
        unsafe { val.write(p.cast()) };
        1
    }
}

ffi_callback! {
    /// `x509_name_ex_free`.
    ///
    /// # Safety
    /// `pval` is NULL or holds NULL or a live name.
    pub(crate) unsafe extern "C" fn ex_free(pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM)
    where failure = (), library = ERR_LIB_ASN1
    {
        if pval.is_null() {
            return;
        }
        // SAFETY: the caller's guarantee.
        let p = unsafe { pval.read() }.cast::<Name>();
        // SAFETY: as above.
        let Some(n) = (unsafe { p.as_mut() }) else { return };
        // SAFETY: the name's own buffer.
        unsafe { BUF_MEM_free(n.bytes) };
        // SAFETY: the name's own entries.
        unsafe { OPENSSL_sk_pop_free(n.entries, Some(free_entry)) };
        // SAFETY: the name's own encoding, or NULL.
        unsafe { mem::release(n.canon_enc.cast()) };
        // SAFETY: the structure.
        unsafe { mem::release(p.cast()) };
        // SAFETY: the caller's slot.
        unsafe { pval.write(ptr::null_mut()) };
    }
}

ffi_callback! {
    /// `x509_name_ex_d2i`: the RDNs (read within `X509_NAME_MAX`), their entries in order
    /// with their RDNs' numbers, the DER kept, and the canonical encoding made.
    ///
    /// # Safety
    /// As for `ASN1_item_ex_d2i`.
    pub(crate) unsafe extern "C" fn ex_d2i(val: *mut *mut ASN1_VALUE, input: *mut *const c_uchar, len: c_long, _it: *const ASN1_ITEM, tag: c_int, aclass: c_int, opt: c_char, ctx: *mut ASN1_TLC) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let q = unsafe { input.read() };
        let mut p = q;
        let mut intname: *mut ASN1_VALUE = ptr::null_mut();
        // SAFETY: as above; the internal item.
        let ret = unsafe { ASN1_item_ex_d2i(&raw mut intname, &raw mut p, len.min(NAME_MAX), internal_it(), tag, aclass, opt, ctx) };
        if ret <= 0 {
            return ret;
        }
        let rdns = intname.cast::<OPENSSL_STACK>();
        // SAFETY: the caller's slot.
        if !unsafe { val.read() }.is_null() {
            // SAFETY: as above.
            unsafe { ex_free(val, ptr::null()) };
        }
        let fail = |nm: *mut ASN1_VALUE| {
            if !nm.is_null() {
                // SAFETY: the name made here.
                unsafe { X509_NAME_free(nm.cast()) };
            }
            // SAFETY: the RDNs decoded, with what entries are still theirs.
            unsafe { OPENSSL_sk_pop_free(rdns, Some(pop_free_rdn)) };
            err::raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR, "x509_name_ex_d2i");
            0
        };
        let mut nm: *mut ASN1_VALUE = ptr::null_mut();
        // SAFETY: a local slot.
        if unsafe { ex_new(&raw mut nm, ptr::null()) } == 0 {
            return fail(nm);
        }
        // SAFETY: just made.
        let Some(n) = (unsafe { name_of(nm.cast()) }) else { return fail(nm) };
        // SAFETY: the decoder moved `p` within the input.
        let used = usize::try_from(unsafe { p.offset_from(q) }).unwrap_or(0);
        // SAFETY: the name's buffer.
        if unsafe { BUF_MEM_grow(n.bytes, used) } == 0 {
            return fail(nm);
        }
        // SAFETY: the name's buffer.
        let dst = unsafe { (*n.bytes).data };
        // SAFETY: the octets read; the buffer grown to them.
        unsafe { ptr::copy_nonoverlapping(q, dst.cast(), used) };
        // SAFETY: the decoded RDNs.
        for i in 0..unsafe { sk_num(rdns) } {
            // SAFETY: as above.
            let rdn = unsafe { OPENSSL_sk_value(rdns, i) }.cast::<OPENSSL_STACK>();
            // SAFETY: an RDN, a stack of entries.
            for j in 0..unsafe { sk_num(rdn) } {
                // SAFETY: as above.
                let e = unsafe { OPENSSL_sk_value(rdn, j) };
                // SAFETY: an entry of the RDN.
                if let Some(entry) = unsafe { entry_of(e.cast()) } {
                    entry.set = i;
                }
                // SAFETY: the name's stack; the entry, moved to it.
                if unsafe { OPENSSL_sk_push(n.entries, e) } == 0 {
                    return fail(nm);
                }
                // SAFETY: the RDN gives the entry up.
                unsafe { OPENSSL_sk_set(rdn, j, ptr::null()) };
            }
        }
        if !canon(n) {
            return fail(nm);
        }
        // SAFETY: the RDNs, now without entries.
        unsafe { OPENSSL_sk_pop_free(rdns, Some(free_rdn)) };
        n.modified = 0;
        // SAFETY: the caller's slots.
        unsafe { val.write(nm) };
        // SAFETY: as above.
        unsafe { input.write(p) };
        ret
    }
}

/// The name's entries grouped into RDNs (a stack of stacks of the same entries, which the
/// caller frees with `free_rdn`), or NULL.
///
/// # Safety
/// The name is live.
unsafe fn group(n: &Name) -> *mut OPENSSL_STACK {
    // SAFETY: no preconditions.
    let rdns = unsafe { OPENSSL_sk_new_null() };
    if rdns.is_null() {
        return ptr::null_mut();
    }
    let mut rdn: *mut OPENSSL_STACK = ptr::null_mut();
    let mut set = -1;
    // SAFETY: the name's entries.
    for i in 0..unsafe { sk_num(n.entries) } {
        // SAFETY: as above.
        let e = unsafe { OPENSSL_sk_value(n.entries, i) };
        // SAFETY: an entry of the name.
        let es = unsafe { entry_of(e.cast()) }.map_or(0, |e| e.set);
        if rdn.is_null() || es != set {
            // SAFETY: no preconditions.
            rdn = unsafe { OPENSSL_sk_new_null() };
            // SAFETY: the new RDN, onto the RDNs.
            if rdn.is_null() || unsafe { OPENSSL_sk_push(rdns, rdn.cast()) } == 0 {
                // SAFETY: made above, or NULL.
                unsafe { OPENSSL_sk_free(rdn) };
                // SAFETY: the RDNs made here.
                unsafe { OPENSSL_sk_pop_free(rdns, Some(free_rdn)) };
                return ptr::null_mut();
            }
            set = es;
        }
        // SAFETY: the RDN; an entry the name keeps.
        if unsafe { OPENSSL_sk_push(rdn, e) } == 0 {
            // SAFETY: as above.
            unsafe { OPENSSL_sk_pop_free(rdns, Some(free_rdn)) };
            return ptr::null_mut();
        }
    }
    rdns
}

/// `x509_name_encode`: the DER made again from the entries; its length, or -1.
fn encode(n: &mut Name) -> c_int {
    // SAFETY: the live name.
    let rdns = unsafe { group(n) };
    if rdns.is_null() {
        err::raise(ERR_LIB_ASN1, ERR_R_CRYPTO_LIB, "x509_name_encode");
        return -1;
    }
    let mut v: *const ASN1_VALUE = rdns.cast_const().cast();
    // SAFETY: the RDNs; the internal item.
    let len = unsafe { ASN1_item_ex_i2d(&raw mut v, ptr::null_mut(), internal_it(), -1, -1) };
    let ok = len >= 0
        // SAFETY: the name's buffer.
        && unsafe { BUF_MEM_grow(n.bytes, usize::try_from(len).unwrap_or(0)) } != 0;
    if !ok {
        err::raise(ERR_LIB_ASN1, ERR_R_BUF_LIB, "x509_name_encode");
        // SAFETY: the RDNs made here.
        unsafe { OPENSSL_sk_pop_free(rdns, Some(free_rdn)) };
        return -1;
    }
    // SAFETY: the buffer grown to the encoding.
    let mut out = unsafe { (*n.bytes).data }.cast::<c_uchar>();
    // SAFETY: as above.
    unsafe { ASN1_item_ex_i2d(&raw mut v, &raw mut out, internal_it(), -1, -1) };
    // SAFETY: as above.
    unsafe { OPENSSL_sk_pop_free(rdns, Some(free_rdn)) };
    n.modified = 0;
    len
}

/// ASCII whitespace as `ossl_isspace` takes it.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `asn1_string_canon`: `out` as `in`'s canonical form (for the string types it canonicalizes:
/// UTF-8, with the leading and trailing spaces gone, each run of spaces one space, and ASCII
/// lowercased; other types copied).
///
/// # Safety
/// The strings are live.
unsafe fn string_canon(out: *mut ASN1_STRING, input: *const ASN1_STRING) -> bool {
    const MASK: c_ulong = (B_ASN1_UTF8STRING
        | B_ASN1_BMPSTRING
        | B_ASN1_UNIVERSALSTRING
        | B_ASN1_PRINTABLESTRING
        | B_ASN1_T61STRING
        | B_ASN1_IA5STRING
        | B_ASN1_VISIBLESTRING) as c_ulong;
    // SAFETY: the caller's guarantee.
    let ty = unsafe { (*input).type_ };
    // SAFETY: no preconditions.
    if unsafe { ASN1_tag2bit(ty) } & MASK == 0 {
        // SAFETY: the caller's strings.
        return unsafe { ASN1_STRING_copy(out, input) } != 0;
    }
    // SAFETY: as above.
    let o = unsafe { &mut *out };
    o.type_ = V_ASN1_UTF8STRING;
    // SAFETY: the out string's data slot (its old data is lost, as OpenSSL loses it: the
    // string comes from `X509_NAME_ENTRY_new`, empty).
    o.length = unsafe { ASN1_STRING_to_UTF8(&raw mut o.data, input) };
    if o.length == -1 {
        return false;
    }
    let total = usize::try_from(o.length).unwrap_or(0);
    // SAFETY: the converted data, `total` octets (and a NUL after them).
    let data = unsafe { core::slice::from_raw_parts_mut(o.data, total) };
    let at = |d: &[u8], i: usize| d.get(i).copied().unwrap_or(0);
    // Trim: `from` past the leading spaces, `len` without the trailing ones.
    let mut from = 0usize;
    let mut len = total;
    while len > 0 && is_space(at(data, from)) {
        from += 1;
        len -= 1;
    }
    while len > 0 && is_space(at(data, from + len - 1)) {
        len -= 1;
    }
    let mut to = 0usize;
    let mut i = 0usize;
    while i < len {
        let c = at(data, from);
        if !c.is_ascii() {
            put(data, to, c);
            to += 1;
            from += 1;
            i += 1;
        } else if is_space(c) {
            put(data, to, b' ');
            to += 1;
            // As OpenSSL's, the run of spaces may go on past `len` (into the trailing ones,
            // up to the NUL).
            loop {
                from += 1;
                i += 1;
                if !is_space(at(data, from)) {
                    break;
                }
            }
        } else {
            put(data, to, c.to_ascii_lowercase());
            to += 1;
            from += 1;
            i += 1;
        }
    }
    o.length = c_int::try_from(to).unwrap_or(0);
    true
}

/// `x509_name_canon`: the canonical encoding made again (none for a name without entries).
fn canon(n: &mut Name) -> bool {
    // SAFETY: the name's own encoding, or NULL.
    unsafe { mem::release(n.canon_enc.cast()) };
    n.canon_enc = ptr::null_mut();
    // SAFETY: the name's entries.
    if unsafe { sk_num(n.entries) } == 0 {
        n.canon_enclen = 0;
        return true;
    }
    // Canonical copies of the entries, grouped into RDNs.
    // SAFETY: no preconditions.
    let rdns = unsafe { OPENSSL_sk_new_null() };
    if rdns.is_null() {
        err::raise(ERR_LIB_X509, ERR_R_CRYPTO_LIB, "x509_name_canon");
        return false;
    }
    let done = |ok: bool| {
        // SAFETY: the RDNs made here, with their copies.
        unsafe { OPENSSL_sk_pop_free(rdns, Some(pop_free_rdn)) };
        ok
    };
    let mut rdn: *mut OPENSSL_STACK = ptr::null_mut();
    let mut set = -1;
    // SAFETY: the name's entries.
    for i in 0..unsafe { sk_num(n.entries) } {
        // SAFETY: as above.
        let Some(e) = (unsafe { sk_entry(n.entries, i) }) else {
            return done(false);
        };
        if rdn.is_null() || e.set != set {
            // SAFETY: no preconditions.
            rdn = unsafe { OPENSSL_sk_new_null() };
            if rdn.is_null() {
                return done(false);
            }
            // SAFETY: the RDNs; the new RDN.
            if unsafe { OPENSSL_sk_push(rdns, rdn.cast()) } == 0 {
                // SAFETY: made above.
                unsafe { OPENSSL_sk_free(rdn) };
                err::raise(ERR_LIB_X509, ERR_R_CRYPTO_LIB, "x509_name_canon");
                return done(false);
            }
            set = e.set;
        }
        // SAFETY: no preconditions.
        let tmp = unsafe { X509_NAME_ENTRY_new() };
        // SAFETY: just made, or NULL.
        let Some(t) = (unsafe { entry_of(tmp) }) else {
            err::raise(ERR_LIB_X509, ERR_R_ASN1_LIB, "x509_name_canon");
            return done(false);
        };
        // SAFETY: the entry's object.
        t.object = unsafe { OBJ_dup(e.object) };
        if t.object.is_null() {
            err::raise(ERR_LIB_X509, ERR_R_OBJ_LIB, "x509_name_canon");
            // SAFETY: made above.
            unsafe { X509_NAME_ENTRY_free(tmp) };
            return done(false);
        }
        // SAFETY: the copy's string; the entry's.
        if !unsafe { string_canon(t.value, e.value) } {
            // SAFETY: as above.
            unsafe { X509_NAME_ENTRY_free(tmp) };
            return done(false);
        }
        // SAFETY: the RDN; the copy.
        if unsafe { OPENSSL_sk_push(rdn, tmp.cast()) } == 0 {
            err::raise(ERR_LIB_X509, ERR_R_CRYPTO_LIB, "x509_name_canon");
            // SAFETY: as above.
            unsafe { X509_NAME_ENTRY_free(tmp) };
            return done(false);
        }
    }
    // `i2d_name_canon`: the RDNs' encodings concatenated.
    let encode_rdns = |out: *mut *mut c_uchar| -> c_int {
        let mut len: c_int = 0;
        // SAFETY: the RDNs.
        for i in 0..unsafe { sk_num(rdns) } {
            // SAFETY: as above.
            let mut v: *const ASN1_VALUE = unsafe { OPENSSL_sk_value(rdns, i) }.cast();
            // SAFETY: an RDN; the RDN item; `out` NULL or room.
            let l = unsafe { ASN1_item_ex_i2d(&raw mut v, out, entries_it(), -1, -1) };
            if l < 0 || len > c_int::MAX - l {
                return -1;
            }
            len += l;
        }
        len
    };
    let len = encode_rdns(ptr::null_mut());
    if len < 0 {
        return done(false);
    }
    n.canon_enclen = len;
    let p: *mut c_uchar = mem::alloc(usize::try_from(len).unwrap_or(0)).cast();
    if p.is_null() {
        return done(false);
    }
    n.canon_enc = p;
    let mut out = p;
    encode_rdns(&raw mut out);
    done(true)
}

ffi_callback! {
    /// `x509_name_ex_i2d`: the DER kept (made again first if the name has changed).
    ///
    /// # Safety
    /// As for `ASN1_item_ex_i2d`.
    pub(crate) unsafe extern "C" fn ex_i2d(val: *mut *const ASN1_VALUE, out: *mut *mut c_uchar, _it: *const ASN1_ITEM, _tag: c_int, _aclass: c_int) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let v = unsafe { val.read() };
        // SAFETY: the caller's guarantee.
        let Some(n) = (unsafe { name_of(v.cast()) }) else { return -1 };
        if n.modified != 0 {
            let r = encode(n);
            if r < 0 {
                return r;
            }
            if !canon(n) {
                return -1;
            }
        }
        // SAFETY: the name's buffer.
        let b = unsafe { &*n.bytes };
        let ret = c_int::try_from(b.length).unwrap_or(-1);
        if !out.is_null() {
            // SAFETY: the caller's pointer.
            let dst = unsafe { out.read() };
            // SAFETY: the caller's room for the encoding.
            unsafe { ptr::copy_nonoverlapping(b.data.cast::<u8>(), dst, b.length) };
            // SAFETY: as above.
            unsafe { out.write(dst.wrapping_add(b.length)) };
        }
        ret
    }
}

ffi_callback! {
    /// `x509_name_ex_print`: `X509_NAME_print_ex` with the context's name flags.
    ///
    /// # Safety
    /// As for an extern item's print.
    pub(crate) unsafe extern "C" fn ex_print(out: *mut BIO, pval: *mut *const ASN1_VALUE, indent: c_int, _fname: *const c_char, pctx: *const ASN1_PCTX) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's context.
        let flags = unsafe { crate::asn1::tpl::print::ASN1_PCTX_get_nm_flags(pctx) };
        // SAFETY: the caller's guarantee.
        let v = unsafe { pval.read() };
        // SAFETY: the caller's guarantee.
        if unsafe { X509_NAME_print_ex(out, v.cast(), indent, flags) } <= 0 {
            return 0;
        }
        2
    }
}

ffi_export! {
    /// Sets `*xn` to a copy of `name` (nothing for the same name): 1, or 0.
    ///
    /// # Safety
    /// `xn` holds NULL or a live name; `name` is NULL or a live name.
    pub unsafe extern "C" fn X509_NAME_set(xn: *mut *mut X509_NAME, name: *const X509_NAME) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let cur = unsafe { xn.read() };
        if ptr::eq(cur, name) {
            return c_int::from(!cur.is_null());
        }
        // SAFETY: as above.
        let copy = unsafe { X509_NAME_dup(name) };
        if copy.is_null() {
            return 0;
        }
        // SAFETY: the old name, given up.
        unsafe { X509_NAME_free(cur) };
        // SAFETY: the caller's slot.
        unsafe { xn.write(copy) };
        1
    }
}

ffi_export! {
    /// The name's DER (kept by the name) and its length: 1, or 0.
    ///
    /// # Safety
    /// `nm` is a live name; `pder` and `pderlen` are NULL or writable.
    pub unsafe extern "C" fn X509_NAME_get0_der(nm: *const X509_NAME, pder: *mut *const c_uchar, pderlen: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if unsafe { i2d_X509_NAME(nm, ptr::null_mut()) } <= 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(n) = (unsafe { name_of(nm) }) else { return 0 };
        // SAFETY: the name's buffer.
        let b = unsafe { &*n.bytes };
        if !pder.is_null() {
            // SAFETY: the caller's slot.
            unsafe { pder.write(b.data.cast()) };
        }
        if !pderlen.is_null() {
            // SAFETY: as above.
            unsafe { pderlen.write(b.length) };
        }
        1
    }
}

// ---- Entries (`x509name.c`) ----

ffi_export! {
    /// The number of entries (0 for NULL).
    ///
    /// # Safety
    /// `name` is NULL or a live name.
    pub unsafe extern "C" fn X509_NAME_entry_count(name: *const X509_NAME) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { name_of(name) }.map_or(0, |n| {
            // SAFETY: the name's entries.
            unsafe { sk_num(n.entries) }
        })
    }
}

ffi_export! {
    /// The index of the next entry after `lastpos` of the object, or -1.
    ///
    /// # Safety
    /// `name` is NULL or a live name; `obj` is a live object.
    pub unsafe extern "C" fn X509_NAME_get_index_by_OBJ(name: *const X509_NAME, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(n) = (unsafe { name_of(name) }) else { return -1 };
        // SAFETY: the name's entries.
        let count = unsafe { sk_num(n.entries) };
        let start = lastpos.max(-1).saturating_add(1);
        for i in start..count {
            // SAFETY: as above.
            let Some(e) = (unsafe { sk_entry(n.entries, i) }) else { continue };
            // SAFETY: the entry's object; the caller's.
            if unsafe { OBJ_cmp(e.object, obj) } == 0 {
                return i;
            }
        }
        -1
    }
}

ffi_export! {
    /// The index of the next entry after `lastpos` of the NID, -1 for none, or -2 for an
    /// unknown NID.
    ///
    /// # Safety
    /// `name` is NULL or a live name.
    pub unsafe extern "C" fn X509_NAME_get_index_by_NID(name: *const X509_NAME, nid: c_int, lastpos: c_int) -> c_int
    where failure = -2, library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let obj = unsafe { OBJ_nid2obj(nid) };
        if obj.is_null() {
            return -2;
        }
        // SAFETY: the caller's guarantee; a built-in object.
        unsafe { X509_NAME_get_index_by_OBJ(name, obj, lastpos) }
    }
}

ffi_export! {
    /// Entry `loc`, or NULL.
    ///
    /// # Safety
    /// `name` is NULL or a live name.
    pub unsafe extern "C" fn X509_NAME_get_entry(name: *const X509_NAME, loc: c_int) -> *mut X509_NAME_ENTRY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(n) = (unsafe { name_of(name) }) else { return ptr::null_mut() };
        // SAFETY: the name's entries.
        if loc < 0 || unsafe { sk_num(n.entries) } <= loc {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        unsafe { OPENSSL_sk_value(n.entries, loc) }.cast()
    }
}

ffi_export! {
    /// The text of the first entry of the object into `buf` (up to `len - 1` octets and a NUL):
    /// its length, the data's length for no buffer, or -1 for none.
    ///
    /// # Safety
    /// `name` is NULL or a live name; `obj` is a live object; `buf` is NULL or has room for
    /// `len` octets.
    pub unsafe extern "C" fn X509_NAME_get_text_by_OBJ(name: *const X509_NAME, obj: *const ASN1_OBJECT, buf: *mut c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let i = unsafe { X509_NAME_get_index_by_OBJ(name, obj, -1) };
        if i < 0 {
            return -1;
        }
        // SAFETY: as above; an index found.
        let e = unsafe { X509_NAME_get_entry(name, i) };
        // SAFETY: the entry.
        let Some(d) = (unsafe { entry_of(e) }).and_then(|e| {
            // SAFETY: the entry's value.
            unsafe { e.value.as_ref() }
        }) else {
            return -1;
        };
        if buf.is_null() {
            return d.length;
        }
        if len <= 0 {
            return 0;
        }
        let n = d.length.min(len - 1).max(0);
        let un = usize::try_from(n).unwrap_or(0);
        // SAFETY: the value's data; the caller's room for `len` octets.
        unsafe { ptr::copy_nonoverlapping(d.data, buf.cast(), un) };
        // SAFETY: as above.
        unsafe { buf.wrapping_add(un).write(0) };
        n
    }
}

ffi_export! {
    /// `X509_NAME_get_text_by_OBJ` of a NID's object (-1 for an unknown NID).
    ///
    /// # Safety
    /// As for `X509_NAME_get_text_by_OBJ`.
    pub unsafe extern "C" fn X509_NAME_get_text_by_NID(name: *const X509_NAME, nid: c_int, buf: *mut c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let obj = unsafe { OBJ_nid2obj(nid) };
        if obj.is_null() {
            return -1;
        }
        // SAFETY: the caller's guarantee; a built-in object.
        unsafe { X509_NAME_get_text_by_OBJ(name, obj, buf, len) }
    }
}

ffi_export! {
    /// Removes entry `loc` and returns it (the caller's), renumbering the RDNs after it if
    /// it was alone in its own; NULL for none.
    ///
    /// # Safety
    /// `name` is NULL or a live name.
    pub unsafe extern "C" fn X509_NAME_delete_entry(name: *mut X509_NAME, loc: c_int) -> *mut X509_NAME_ENTRY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(n) = (unsafe { name_of(name) }) else { return ptr::null_mut() };
        // SAFETY: the name's entries.
        if loc < 0 || unsafe { sk_num(n.entries) } <= loc {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        let ret = unsafe { OPENSSL_sk_delete(n.entries, loc) }.cast::<X509_NAME_ENTRY>();
        // SAFETY: as above.
        let count = unsafe { sk_num(n.entries) };
        n.modified = 1;
        if loc == count {
            return ret;
        }
        // SAFETY: the removed entry.
        let ret_set = unsafe { entry_of(ret) }.map_or(0, |e| e.set);
        let set_prev = if loc != 0 {
            // SAFETY: the entry before.
            unsafe { sk_entry(n.entries, loc - 1) }.map_or(0, |e| e.set)
        } else {
            ret_set - 1
        };
        // SAFETY: the entry now at `loc`.
        let set_next = unsafe { sk_entry(n.entries, loc) }.map_or(0, |e| e.set);
        if set_prev + 1 < set_next {
            for i in loc..count {
                // SAFETY: as above.
                if let Some(e) = unsafe { sk_entry(n.entries, i) } {
                    e.set -= 1;
                }
            }
        }
        ret
    }
}

ffi_export! {
    /// Adds a copy of the entry at `loc` (the end for one out of range): in a new RDN (`set` 0,
    /// renumbering those after), in the RDN before it (-1), or in the RDN at `loc` (other
    /// values; the next RDN at the end). 1, or 0.
    ///
    /// # Safety
    /// `name` is NULL or a live name; `ne` is a live entry.
    pub unsafe extern "C" fn X509_NAME_add_entry(name: *mut X509_NAME, ne: *const X509_NAME_ENTRY, loc: c_int, set: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(n) = (unsafe { name_of(name) }) else { return 0 };
        // SAFETY: the name's entries.
        let count = unsafe { sk_num(n.entries) };
        let loc = if loc > count || loc < 0 { count } else { loc };
        let mut inc = set == 0;
        n.modified = 1;
        let set_of = |i: c_int| {
            // SAFETY: the name's entry.
            unsafe { sk_entry(n.entries, i) }.map_or(0, |e| e.set)
        };
        let set = if set == -1 {
            if loc == 0 {
                inc = true;
                0
            } else {
                set_of(loc - 1)
            }
        } else if loc >= count {
            if loc != 0 { set_of(loc - 1) + 1 } else { 0 }
        } else {
            set_of(loc)
        };
        // SAFETY: the caller's entry.
        let copy = unsafe { X509_NAME_ENTRY_dup(ne) };
        // SAFETY: just made, or NULL.
        let Some(c) = (unsafe { entry_of(copy) }) else { return 0 };
        c.set = set;
        // SAFETY: the name's entries; the copy.
        if unsafe { OPENSSL_sk_insert(n.entries, copy.cast(), loc) } == 0 {
            err::raise(ERR_LIB_X509, ERR_R_CRYPTO_LIB, "X509_NAME_add_entry");
            // SAFETY: as above.
            unsafe { X509_NAME_ENTRY_free(copy) };
            return 0;
        }
        if inc {
            // SAFETY: the name's entries.
            let count = unsafe { sk_num(n.entries) };
            for i in loc + 1..count {
                // SAFETY: as above.
                if let Some(e) = unsafe { sk_entry(n.entries, i) } {
                    e.set += 1;
                }
            }
        }
        1
    }
}

ffi_export! {
    /// Adds an entry of the object and value (see `X509_NAME_ENTRY_set_data`): 1, or 0.
    ///
    /// # Safety
    /// `name` is NULL or a live name; `obj` is NULL or a live object; `bytes` is NULL or holds
    /// `len` octets (a NUL-terminated string for a negative `len`).
    pub unsafe extern "C" fn X509_NAME_add_entry_by_OBJ(name: *mut X509_NAME, obj: *const ASN1_OBJECT, type_: c_int, bytes: *const c_uchar, len: c_int, loc: c_int, set: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let ne = unsafe { X509_NAME_ENTRY_create_by_OBJ(ptr::null_mut(), obj, type_, bytes, len) };
        if ne.is_null() {
            return 0;
        }
        // SAFETY: as above; the entry made.
        let ret = unsafe { X509_NAME_add_entry(name, ne, loc, set) };
        // SAFETY: as above.
        unsafe { X509_NAME_ENTRY_free(ne) };
        ret
    }
}

ffi_export! {
    /// `X509_NAME_add_entry_by_OBJ` of a NID's object.
    ///
    /// # Safety
    /// As for `X509_NAME_add_entry_by_OBJ`.
    pub unsafe extern "C" fn X509_NAME_add_entry_by_NID(name: *mut X509_NAME, nid: c_int, type_: c_int, bytes: *const c_uchar, len: c_int, loc: c_int, set: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let ne = unsafe { X509_NAME_ENTRY_create_by_NID(ptr::null_mut(), nid, type_, bytes, len) };
        if ne.is_null() {
            return 0;
        }
        // SAFETY: as above; the entry made.
        let ret = unsafe { X509_NAME_add_entry(name, ne, loc, set) };
        // SAFETY: as above.
        unsafe { X509_NAME_ENTRY_free(ne) };
        ret
    }
}

ffi_export! {
    /// `X509_NAME_add_entry_by_OBJ` of the object a name or dotted OID gives.
    ///
    /// # Safety
    /// As for `X509_NAME_add_entry_by_OBJ`, with `field` a string.
    pub unsafe extern "C" fn X509_NAME_add_entry_by_txt(name: *mut X509_NAME, field: *const c_char, type_: c_int, bytes: *const c_uchar, len: c_int, loc: c_int, set: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let ne = unsafe { X509_NAME_ENTRY_create_by_txt(ptr::null_mut(), field, type_, bytes, len) };
        if ne.is_null() {
            return 0;
        }
        // SAFETY: as above; the entry made.
        let ret = unsafe { X509_NAME_add_entry(name, ne, loc, set) };
        // SAFETY: as above.
        unsafe { X509_NAME_ENTRY_free(ne) };
        ret
    }
}

ffi_export! {
    /// An entry (`*ne`, or a new one) of the object a name or OID gives and the value; NULL
    /// with `X509_R_INVALID_FIELD_NAME` for a name there's none of.
    ///
    /// # Safety
    /// `ne` is NULL or holds NULL or a live entry; `field` is a string; `bytes` as for
    /// `X509_NAME_ENTRY_set_data`.
    pub unsafe extern "C" fn X509_NAME_ENTRY_create_by_txt(ne: *mut *mut X509_NAME_ENTRY, field: *const c_char, type_: c_int, bytes: *const c_uchar, len: c_int) -> *mut X509_NAME_ENTRY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's string.
        let obj = unsafe { OBJ_txt2obj(field, 0) };
        if obj.is_null() {
            // SAFETY: as above.
            let f = unsafe { crate::asn1::tpl::cstr_bytes(field) }.unwrap_or_default();
            err::raise_with_text(ERR_LIB_X509, X509_R_INVALID_FIELD_NAME, "X509_NAME_ENTRY_create_by_txt", &format!("name={}", String::from_utf8_lossy(f)));
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee; the object made.
        let e = unsafe { X509_NAME_ENTRY_create_by_OBJ(ne, obj, type_, bytes, len) };
        // SAFETY: as above.
        unsafe { ASN1_OBJECT_free(obj) };
        e
    }
}

ffi_export! {
    /// An entry of a NID's object and the value; NULL with `X509_R_UNKNOWN_NID` for an
    /// unknown NID.
    ///
    /// # Safety
    /// As for `X509_NAME_ENTRY_create_by_OBJ`.
    pub unsafe extern "C" fn X509_NAME_ENTRY_create_by_NID(ne: *mut *mut X509_NAME_ENTRY, nid: c_int, type_: c_int, bytes: *const c_uchar, len: c_int) -> *mut X509_NAME_ENTRY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let obj = unsafe { OBJ_nid2obj(nid) };
        if obj.is_null() {
            err::raise(ERR_LIB_X509, X509_R_UNKNOWN_NID, "X509_NAME_ENTRY_create_by_NID");
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee; a built-in object.
        let e = unsafe { X509_NAME_ENTRY_create_by_OBJ(ne, obj, type_, bytes, len) };
        // SAFETY: as above (a no-op for a built-in object).
        unsafe { ASN1_OBJECT_free(obj) };
        e
    }
}

ffi_export! {
    /// The entry `*ne` (or a new one, stored in `*ne` when it was NULL) with the object and
    /// value; NULL on failure.
    ///
    /// # Safety
    /// `ne` is NULL or holds NULL or a live entry; `obj` is NULL or a live object; `bytes` as
    /// for `X509_NAME_ENTRY_set_data`.
    pub unsafe extern "C" fn X509_NAME_ENTRY_create_by_OBJ(ne: *mut *mut X509_NAME_ENTRY, obj: *const ASN1_OBJECT, type_: c_int, bytes: *const c_uchar, len: c_int) -> *mut X509_NAME_ENTRY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let given = if ne.is_null() { ptr::null_mut() } else { unsafe { ne.read() } };
        let ret = if given.is_null() {
            // SAFETY: no preconditions.
            let r = unsafe { X509_NAME_ENTRY_new() };
            if r.is_null() {
                return ptr::null_mut();
            }
            r
        } else {
            given
        };
        // SAFETY: the entry; the caller's object and value.
        let ok = unsafe { X509_NAME_ENTRY_set_object(ret, obj) } != 0
            // SAFETY: as above.
            && unsafe { X509_NAME_ENTRY_set_data(ret, type_, bytes, len) } != 0;
        if !ok {
            if given.is_null() {
                // SAFETY: made above.
                unsafe { X509_NAME_ENTRY_free(ret) };
            }
            return ptr::null_mut();
        }
        if !ne.is_null() && given.is_null() {
            // SAFETY: the caller's slot.
            unsafe { ne.write(ret) };
        }
        ret
    }
}

ffi_export! {
    /// Sets the entry's object (a copy): 1, or 0.
    ///
    /// # Safety
    /// `ne` is NULL or a live entry; `obj` is NULL or a live object.
    pub unsafe extern "C" fn X509_NAME_ENTRY_set_object(ne: *mut X509_NAME_ENTRY, obj: *const ASN1_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(e) = (unsafe { entry_of(ne) }).filter(|_| !obj.is_null()) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509_NAME_ENTRY_set_object");
            return 0;
        };
        // SAFETY: the entry's object, given up.
        unsafe { ASN1_OBJECT_free(e.object) };
        // SAFETY: the caller's object.
        e.object = unsafe { OBJ_dup(obj) };
        c_int::from(!e.object.is_null())
    }
}

ffi_export! {
    /// Sets the entry's value: a multibyte string converted for its object's NID (`type` an
    /// `MBSTRING_*`), else the octets (a NUL-terminated string for a negative `len`) of the
    /// type (the printable type that fits for `V_ASN1_APP_CHOOSE`, the string's own for
    /// `V_ASN1_UNDEF`). 1, or 0.
    ///
    /// # Safety
    /// `ne` is NULL or a live entry; `bytes` is NULL (with `len` 0) or holds `len` octets (a
    /// NUL-terminated string for a negative `len`).
    pub unsafe extern "C" fn X509_NAME_ENTRY_set_data(ne: *mut X509_NAME_ENTRY, type_: c_int, bytes: *const c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(e) = (unsafe { entry_of(ne) }) else { return 0 };
        if bytes.is_null() && len != 0 {
            return 0;
        }
        if type_ > 0 && type_ & MBSTRING_FLAG != 0 {
            // SAFETY: the entry's object.
            let nid = unsafe { OBJ_obj2nid(e.object) };
            // SAFETY: the entry's value slot; the caller's octets.
            let r = unsafe { ASN1_STRING_set_by_NID(&raw mut e.value, bytes, len, type_, nid) };
            return c_int::from(!r.is_null());
        }
        let len = if len < 0 {
            // SAFETY: a NUL-terminated string (the caller's guarantee).
            c_int::try_from(unsafe { libc::strlen(bytes.cast()) }).unwrap_or(c_int::MAX)
        } else {
            len
        };
        // SAFETY: the entry's value; the caller's octets.
        if unsafe { ASN1_STRING_set(e.value, bytes.cast(), len) } == 0 {
            return 0;
        }
        if type_ != V_ASN1_UNDEF {
            // SAFETY: the value just set.
            let v = unsafe { &mut *e.value };
            v.type_ = if type_ == V_ASN1_APP_CHOOSE {
                // SAFETY: the caller's octets.
                unsafe { ASN1_PRINTABLE_type(bytes, len) }
            } else {
                type_
            };
        }
        1
    }
}

ffi_export! {
    /// The entry's object (the entry's), or NULL.
    ///
    /// # Safety
    /// `ne` is NULL or a live entry.
    pub unsafe extern "C" fn X509_NAME_ENTRY_get_object(ne: *const X509_NAME_ENTRY) -> *mut ASN1_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { entry_of(ne) }.map_or(ptr::null_mut(), |e| e.object)
    }
}

ffi_export! {
    /// The entry's value (the entry's), or NULL.
    ///
    /// # Safety
    /// `ne` is NULL or a live entry.
    pub unsafe extern "C" fn X509_NAME_ENTRY_get_data(ne: *const X509_NAME_ENTRY) -> *mut ASN1_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { entry_of(ne) }.map_or(ptr::null_mut(), |e| e.value)
    }
}

ffi_export! {
    /// The number of the RDN the entry is in (as OpenSSL's, it reads the entry: NULL isn't
    /// taken).
    ///
    /// # Safety
    /// `ne` is a live entry.
    pub unsafe extern "C" fn X509_NAME_ENTRY_set(ne: *const X509_NAME_ENTRY) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee (NULL answers 0, where OpenSSL would crash).
        unsafe { entry_of(ne) }.map_or(0, |e| e.set)
    }
}

// ---- One line (`x509_obj.c`) ----

ffi_export! {
    /// The name as "/type=value..." ('+' between the entries of one RDN; '/' and '+' escaped,
    /// other octets outside ' '..'~' as `\xHH`), into `buf` (`len` octets, the entries that
    /// don't fit left out) or a new buffer for NULL (the caller's to free); NULL on failure or
    /// for `len` 0.
    ///
    /// # Safety
    /// `a` is NULL or a live name; `buf` is NULL or has room for `len` octets.
    pub unsafe extern "C" fn X509_NAME_oneline(a: *const X509_NAME, buf: *mut c_char, len: c_int) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        const F: &str = "X509_NAME_oneline";
        if !buf.is_null() && len == 0 {
            return ptr::null_mut();
        }
        let mut out: Vec<u8> = Vec::new();
        let room = if buf.is_null() { None } else { Some(usize::try_from(len.saturating_sub(1)).unwrap_or(0)) };
        // SAFETY: the caller's guarantee.
        let Some(n) = (unsafe { name_of(a) }) else {
            let text = b"NO X509_NAME";
            return match room {
                // `strncpy(buf, "NO X509_NAME", len); buf[len - 1] = '\0'`.
                Some(_) => {
                    let ul = usize::try_from(len).unwrap_or(0);
                    for i in 0..ul {
                        // SAFETY: the caller's room for `len` octets.
                        unsafe { buf.wrapping_add(i).write(c_char::from_ne_bytes([text.get(i).copied().unwrap_or(0)])) };
                    }
                    // SAFETY: as above.
                    unsafe { buf.wrapping_add(ul - 1).write(0) };
                    buf
                }
                None => copy_out(text, F),
            };
        };
        let mut prev_set = -1;
        let mut l: c_int = 0;
        // SAFETY: the name's entries.
        for i in 0..unsafe { sk_num(n.entries) } {
            // SAFETY: as above.
            let Some(e) = (unsafe { sk_entry(n.entries, i) }) else { continue };
            // SAFETY: the entry's object.
            let nid = unsafe { OBJ_obj2nid(e.object) };
            // SAFETY: no preconditions.
            let sn = if nid == NID_undef { ptr::null() } else { unsafe { OBJ_nid2sn(nid) } };
            let mut tmp = [0 as c_char; 80];
            let s: Vec<u8> = if sn.is_null() {
                // SAFETY: room for 80; the entry's object.
                unsafe { i2t_ASN1_OBJECT(tmp.as_mut_ptr(), 80, e.object) };
                // SAFETY: the NUL-terminated text written.
                unsafe { core::ffi::CStr::from_ptr(tmp.as_ptr()) }.to_bytes().to_vec()
            } else {
                // SAFETY: a static name.
                unsafe { core::ffi::CStr::from_ptr(sn) }.to_bytes().to_vec()
            };
            // SAFETY: the entry's value.
            let v = unsafe { &*e.value };
            let num = v.length;
            if num > ONELINE_MAX {
                err::raise(ERR_LIB_X509, X509_R_NAME_TOO_LONG, F);
                return ptr::null_mut();
            }
            // SAFETY: the value's data holds its length.
            let q = unsafe { crate::asn1::text::octets(v.data, num) };
            // A GeneralString of 4-octet characters with only the last octets set: those.
            let mut doit = [true; 4];
            if v.type_ == V_ASN1_GENERALSTRING && num % 4 == 0 {
                let mut seen = [false; 4];
                for (j, &c) in q.iter().enumerate() {
                    if c != 0 {
                        put(&mut seen, j & 3, true);
                    }
                }
                doit = if seen[0] || seen[1] || seen[2] { [true; 4] } else { [false, false, false, true] };
            }
            let mut l2: c_int = 0;
            for (j, &c) in q.iter().enumerate() {
                if !doit.get(j & 3).copied().unwrap_or(false) {
                    continue;
                }
                l2 += 1;
                if c == b'/' || c == b'+' {
                    l2 += 1;
                } else if !(b' '..=b'~').contains(&c) {
                    l2 += 3;
                }
            }
            let l1 = c_int::try_from(s.len()).unwrap_or(0);
            l = l.saturating_add(1 + l1 + 1 + l2);
            if l > ONELINE_MAX {
                err::raise(ERR_LIB_X509, X509_R_NAME_TOO_LONG, F);
                return ptr::null_mut();
            }
            if let Some(r) = room
                && usize::try_from(l).unwrap_or(usize::MAX) > r
            {
                break;
            }
            out.push(if prev_set == e.set { b'+' } else { b'/' });
            out.extend_from_slice(&s);
            out.push(b'=');
            for (j, &c) in q.iter().enumerate() {
                if !doit.get(j & 3).copied().unwrap_or(false) {
                    continue;
                }
                if !(b' '..=b'~').contains(&c) {
                    out.extend_from_slice(format!("\\x{c:02X}").as_bytes());
                } else {
                    if c == b'/' || c == b'+' {
                        out.push(b'\\');
                    }
                    out.push(c);
                }
            }
            prev_set = e.set;
        }
        match room {
            Some(_) => {
                // SAFETY: the caller's room (what's written fits `len - 1` octets and a NUL).
                unsafe { ptr::copy_nonoverlapping(out.as_ptr(), buf.cast(), out.len()) };
                // SAFETY: as above.
                unsafe { buf.wrapping_add(out.len()).write(0) };
                buf
            }
            None => copy_out(&out, F),
        }
    }
}

/// Sets `data[i]`, if it's there.
fn put<T>(data: &mut [T], i: usize, v: T) {
    if let Some(d) = data.get_mut(i) {
        *d = v;
    }
}

/// A new NUL-terminated copy from the C allocator (OpenSSL grows its buffer to 200 octets
/// at least), or NULL with `ERR_R_BUF_LIB`.
fn copy_out(text: &[u8], f: &str) -> *mut c_char {
    let size = (text.len() + 1).max(200);
    let p: *mut u8 = mem::alloc(size).cast();
    if p.is_null() {
        err::raise(ERR_LIB_X509, ERR_R_BUF_LIB, f);
        return ptr::null_mut();
    }
    // SAFETY: room for the text and a NUL.
    unsafe { ptr::copy_nonoverlapping(text.as_ptr(), p, text.len()) };
    // SAFETY: as above.
    unsafe { p.wrapping_add(text.len()).write(0) };
    p.cast()
}

ffi_export! {
    /// The name as `X509_NAME_oneline` gives it, its entries separated by ", " (at each '/'
    /// that starts an entry): 1, or 0. (`obase` is unused, as it is in OpenSSL.)
    ///
    /// # Safety
    /// `bp` is a live BIO; `name` is NULL or a live name.
    pub unsafe extern "C" fn X509_NAME_print(bp: *mut BIO, name: *const X509_NAME, obase: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        let _ = obase;
        // SAFETY: the caller's guarantee.
        let b = unsafe { X509_NAME_oneline(name, ptr::null_mut(), 0) };
        if b.is_null() {
            return 0;
        }
        // SAFETY: the NUL-terminated line made.
        let line = unsafe { core::ffi::CStr::from_ptr(b) }.to_bytes().to_vec();
        // SAFETY: made above.
        unsafe { mem::release(b.cast()) };
        let Some(rest) = line.get(1..) else { return 1 };
        let at = |i: usize| rest.get(i).copied().unwrap_or(0);
        let mut c = 0usize;
        let mut s = 0usize;
        let write = |chunk: &[u8]| {
            let n = c_int::try_from(chunk.len()).unwrap_or(0);
            // SAFETY: the caller's BIO; the chunk.
            (unsafe { crate::bio::BIO_write(bp, chunk.as_ptr().cast(), n) }) == n
        };
        loop {
            let starts = at(s) == b'/'
                && at(s + 1).is_ascii_uppercase()
                && (at(s + 2) == b'=' || (at(s + 2).is_ascii_uppercase() && at(s + 3) == b'='));
            if starts || at(s) == 0 {
                if !write(rest.get(c..s).unwrap_or_default()) {
                    err::raise(ERR_LIB_X509, ERR_R_BUF_LIB, "X509_NAME_print");
                    return 0;
                }
                c = s + 1;
                if at(s) != 0 && !write(b", ") {
                    err::raise(ERR_LIB_X509, ERR_R_BUF_LIB, "X509_NAME_print");
                    return 0;
                }
            }
            if at(s) == 0 {
                break;
            }
            s += 1;
        }
        1
    }
}

// ---- Comparison and hashes (`x509_cmp.c`) ----

/// `i2d_X509_NAME` of a name to bring its encodings up to date: false on failure.
///
/// # Safety
/// `n` is a live name.
unsafe fn refresh(n: *const X509_NAME) -> bool {
    // SAFETY: the caller's guarantee.
    (unsafe { i2d_X509_NAME(n, ptr::null_mut()) }) >= 0
}

ffi_export! {
    /// Compares the names' canonical encodings (by length first): -1, 0, or 1, and -2 when one
    /// can't be encoded. NULL is less than any name.
    ///
    /// # Safety
    /// `a` and `b` are NULL or live names.
    pub unsafe extern "C" fn X509_NAME_cmp(a: *const X509_NAME, b: *const X509_NAME) -> c_int
    where failure = -2, library = ERR_LIB_X509
    {
        if b.is_null() {
            return c_int::from(!a.is_null());
        }
        if a.is_null() {
            return -1;
        }
        for x in [a, b] {
            // SAFETY: the caller's names.
            let stale = unsafe { name_of(x) }.is_some_and(|n| n.canon_enc.is_null() || n.modified != 0);
            // SAFETY: as above.
            if stale && !unsafe { refresh(x) } {
                return -2;
            }
        }
        // SAFETY: as above.
        let (Some(na), Some(nb)) = (unsafe { name_of(a) }, unsafe { name_of(b) }) else { return -2 };
        let ret = na.canon_enclen - nb.canon_enclen;
        if ret == 0 && na.canon_enclen == 0 {
            return 0;
        }
        let ret = if ret == 0 {
            if na.canon_enc.is_null() || nb.canon_enc.is_null() {
                return -2;
            }
            let ul = usize::try_from(na.canon_enclen).unwrap_or(0);
            // SAFETY: both encodings hold `canon_enclen` octets.
            let x = unsafe { core::slice::from_raw_parts(na.canon_enc, ul) };
            // SAFETY: as above.
            let y = unsafe { core::slice::from_raw_parts(nb.canon_enc, ul) };
            match x.cmp(y) {
                core::cmp::Ordering::Less => -1,
                core::cmp::Ordering::Equal => 0,
                core::cmp::Ordering::Greater => 1,
            }
        } else {
            ret
        };
        if ret < 0 { -1 } else { c_int::from(ret > 0) }
    }
}

/// The first four octets of a digest, little-endian, as the hashes take them.
fn first_word(md: &[u8]) -> c_ulong {
    let w = |i: usize| c_ulong::from(md.get(i).copied().unwrap_or(0));
    (w(0) | (w(1) << 8) | (w(2) << 16) | (w(3) << 24)) & 0xffff_ffff
}

ffi_export! {
    /// The hash of a hashed directory's file names: the first four octets of the SHA-1 of the
    /// canonical encoding, little-endian; 0 (and `*ok` 0) on failure.
    ///
    /// # Safety
    /// `x` is a live name; `libctx` is NULL or live; `propq` is NULL or a string; `ok` is NULL
    /// or writable.
    pub unsafe extern "C" fn X509_NAME_hash_ex(x: *const X509_NAME, libctx: *mut OSSL_LIB_CTX, propq: *const c_char, ok: *mut c_int) -> c_ulong
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's library context and properties; a static name.
        let sha1 = unsafe { crate::evp::digest::EVP_MD_fetch(libctx, c"SHA1".as_ptr(), propq) };
        // SAFETY: the caller's name.
        let encoded = unsafe { refresh(x) };
        if !ok.is_null() {
            // SAFETY: the caller's slot.
            unsafe { ok.write(0) };
        }
        let mut ret = 0;
        // SAFETY: as above.
        if let (true, false, Some(n)) = (encoded, sha1.is_null(), unsafe { name_of(x) }) {
            let mut md = [0u8; 20];
            // SAFETY: the canonical encoding (`canon_enclen` octets, or none); room for SHA-1.
            if unsafe { crate::evp::md_ctx::EVP_Digest(n.canon_enc.cast(), usize::try_from(n.canon_enclen).unwrap_or(0), md.as_mut_ptr(), ptr::null_mut(), sha1, ptr::null_mut()) } != 0 {
                ret = first_word(&md);
                if !ok.is_null() {
                    // SAFETY: as above.
                    unsafe { ok.write(1) };
                }
            }
        }
        // SAFETY: fetched above, or NULL.
        unsafe { crate::evp::digest::EVP_MD_free(sha1) };
        ret
    }
}

ffi_export! {
    /// The old hash (before OpenSSL 1.0.0): the first four octets of the MD5 of the DER,
    /// little-endian; 0 on failure.
    ///
    /// # Safety
    /// `x` is a live name.
    pub unsafe extern "C" fn X509_NAME_hash_old(x: *const X509_NAME) -> c_ulong
    where failure = 0, library = ERR_LIB_X509
    {
        use crate::evp::md_ctx::{EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new};
        // SAFETY: static names.
        let md5 = unsafe { crate::evp::digest::EVP_MD_fetch(ptr::null_mut(), c"MD5".as_ptr(), c"-fips".as_ptr()) };
        // SAFETY: no preconditions.
        let ctx = unsafe { EVP_MD_CTX_new() };
        let mut ret = 0;
        // SAFETY: the caller's name.
        if !md5.is_null() && !ctx.is_null() && unsafe { refresh(x) }
            // SAFETY: as above.
            && let Some(n) = unsafe { name_of(x) }
        {
            // SAFETY: the name's buffer.
            let b = unsafe { &*n.bytes };
            let mut md = [0u8; 16];
            // SAFETY: the context; the digest; the DER; room for MD5.
            let ok = unsafe { EVP_DigestInit_ex(ctx, md5, ptr::null_mut()) } != 0
                // SAFETY: as above.
                && unsafe { EVP_DigestUpdate(ctx, b.data.cast(), b.length) } != 0
                // SAFETY: as above.
                && unsafe { EVP_DigestFinal_ex(ctx, md.as_mut_ptr(), ptr::null_mut()) } != 0;
            if ok {
                ret = first_word(&md);
            }
        }
        // SAFETY: made above, or NULL.
        unsafe { EVP_MD_CTX_free(ctx) };
        // SAFETY: as above.
        unsafe { crate::evp::digest::EVP_MD_free(md5) };
        ret
    }
}

ffi_export! {
    /// The digest of the name's DER into `md` (and its length into `*len`): 1, or 0.
    ///
    /// # Safety
    /// `data` is a live name; `type_` is a live digest; `md` has room for its output; `len` is
    /// NULL or writable.
    pub unsafe extern "C" fn X509_NAME_digest(data: *const X509_NAME, type_: *const EVP_MD, md: *mut c_uchar, len: *mut c_uint) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_NAME_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { crate::asn1::tpl::util::ASN1_item_digest(it, type_, data.cast_mut().cast(), md, len) }
    }
}

// ---- print_ex (`a_strex.c`'s `do_name_ex`) ----

/// The widths `XN_FLAG_FN_ALIGN` pads the short and long names to.
const FN_WIDTH_SN: usize = 10;
const FN_WIDTH_LN: usize = 25;

/// `do_name_ex`: the name written with the flags; the characters written, or -1.
///
/// # Safety
/// `n` is NULL or a live name.
unsafe fn name_ex(
    sink: &mut dyn FnMut(&[u8]) -> bool,
    n: *const X509_NAME,
    indent: c_int,
    flags: c_ulong,
) -> c_int {
    let indent = usize::try_from(indent).unwrap_or(0);
    let spaces = |sink: &mut dyn FnMut(&[u8]) -> bool, k: usize| (0..k).all(|_| sink(b" "));
    let mut outlen = indent;
    if !spaces(sink, indent) {
        return -1;
    }
    let (sep_dn, sep_mv, indent): (&[u8], &[u8], usize) = match flags
        & c_ulong::from(XN_FLAG_SEP_MASK.cast_unsigned())
    {
        f if f == c_ulong::from(XN_FLAG_SEP_MULTILINE.cast_unsigned()) => (b"\n", b" + ", indent),
        f if f == c_ulong::from(XN_FLAG_SEP_COMMA_PLUS.cast_unsigned()) => (b",", b"+", 0),
        f if f == c_ulong::from(XN_FLAG_SEP_CPLUS_SPC.cast_unsigned()) => (b", ", b" + ", 0),
        f if f == c_ulong::from(XN_FLAG_SEP_SPLUS_SPC.cast_unsigned()) => (b"; ", b" + ", 0),
        _ => return -1,
    };
    let sep_eq: &[u8] = if flags & c_ulong::from(XN_FLAG_SPC_EQ.cast_unsigned()) != 0 {
        b" = "
    } else {
        b"="
    };
    let fn_opt = flags & c_ulong::from(XN_FLAG_FN_MASK.cast_unsigned());
    // SAFETY: the caller's guarantee.
    let cnt = unsafe { X509_NAME_entry_count(n) };
    let mut prev = -1;
    for i in 0..cnt {
        let idx = if flags & c_ulong::from(XN_FLAG_DN_REV.cast_unsigned()) != 0 {
            cnt - i - 1
        } else {
            i
        };
        // SAFETY: as above.
        let ent = unsafe { X509_NAME_get_entry(n, idx) };
        // SAFETY: an entry of the name.
        let Some(e) = (unsafe { entry_of(ent) }) else {
            return -1;
        };
        if prev != -1 {
            if prev == e.set {
                if !sink(sep_mv) {
                    return -1;
                }
                outlen += sep_mv.len();
            } else {
                if !sink(sep_dn) || !spaces(sink, indent) {
                    return -1;
                }
                outlen += sep_dn.len() + indent;
            }
        }
        prev = e.set;
        // SAFETY: the entry's object.
        let nid = unsafe { OBJ_obj2nid(e.object) };
        if fn_opt != c_ulong::from(XN_FLAG_FN_NONE.cast_unsigned()) {
            let mut tmp = [0 as c_char; 80];
            let (obj, fld_len): (Vec<u8>, usize) =
                if fn_opt == c_ulong::from(XN_FLAG_FN_OID.cast_unsigned()) || nid == NID_undef {
                    // SAFETY: room for 80; the entry's object.
                    unsafe { OBJ_obj2txt(tmp.as_mut_ptr(), 80, e.object, 1) };
                    // SAFETY: the NUL-terminated text written.
                    (
                        unsafe { core::ffi::CStr::from_ptr(tmp.as_ptr()) }
                            .to_bytes()
                            .to_vec(),
                        0,
                    )
                } else if fn_opt == c_ulong::from(XN_FLAG_FN_SN.cast_unsigned()) {
                    // SAFETY: no preconditions.
                    (cstr_or_empty(unsafe { OBJ_nid2sn(nid) }), FN_WIDTH_SN)
                } else if fn_opt == c_ulong::from(XN_FLAG_FN_LN.cast_unsigned()) {
                    // SAFETY: no preconditions.
                    (cstr_or_empty(unsafe { OBJ_nid2ln(nid) }), FN_WIDTH_LN)
                } else {
                    (Vec::new(), 0)
                };
            if !sink(&obj) {
                return -1;
            }
            if obj.len() < fld_len && flags & c_ulong::from(XN_FLAG_FN_ALIGN.cast_unsigned()) != 0 {
                if !spaces(sink, fld_len - obj.len()) {
                    return -1;
                }
                outlen += fld_len - obj.len();
            }
            if !sink(sep_eq) {
                return -1;
            }
            outlen += obj.len() + sep_eq.len();
        }
        let orflags = if nid == NID_undef
            && flags & c_ulong::from(XN_FLAG_DUMP_UNKNOWN_FIELDS.cast_unsigned()) != 0
        {
            c_ulong::from(ASN1_STRFLGS_DUMP_ALL.cast_unsigned())
        } else {
            0
        };
        // SAFETY: the entry's value.
        let len = unsafe { crate::asn1::text::print_ex(e.value, flags | orflags, Some(sink)) };
        if len < 0 {
            return -1;
        }
        outlen += usize::try_from(len).unwrap_or(0);
    }
    c_int::try_from(outlen).unwrap_or(c_int::MAX)
}

/// A static C string's octets (none for NULL).
fn cstr_or_empty(p: *const c_char) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    // SAFETY: a static name of the object table.
    unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes().to_vec()
}

ffi_export! {
    /// Writes the name with the `XN_FLAG_*` flags (`XN_FLAG_COMPAT` as `X509_NAME_print`):
    /// the characters written, or -1 (0 or 1 for the compatible form).
    ///
    /// # Safety
    /// `out` is a live BIO; `nm` is NULL or a live name.
    pub unsafe extern "C" fn X509_NAME_print_ex(out: *mut BIO, nm: *const X509_NAME, indent: c_int, flags: c_ulong) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        if flags == c_ulong::from(XN_FLAG_COMPAT.cast_unsigned()) {
            // SAFETY: the caller's guarantee.
            return unsafe { X509_NAME_print(out, nm, indent) };
        }
        let mut write = |chunk: &[u8]| {
            let n = c_int::try_from(chunk.len()).unwrap_or(0);
            // SAFETY: the caller's BIO; the chunk.
            (unsafe { crate::bio::BIO_write(out, chunk.as_ptr().cast(), n) }) == n
        };
        // SAFETY: the caller's guarantee.
        unsafe { name_ex(&mut write, nm, indent.max(0), flags) }
    }
}

ffi_export! {
    /// `X509_NAME_print_ex` to a `FILE`.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `nm` is NULL or a live name.
    pub unsafe extern "C" fn X509_NAME_print_ex_fp(fp: *mut FILE, nm: *const X509_NAME, indent: c_int, flags: c_ulong) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        if flags == c_ulong::from(XN_FLAG_COMPAT.cast_unsigned()) {
            // SAFETY: the caller's `FILE`.
            let b = unsafe { crate::bio::file::BIO_new_fp(fp, BIO_NOCLOSE) };
            if b.is_null() {
                return -1;
            }
            // SAFETY: the BIO made; the caller's name.
            let r = unsafe { X509_NAME_print(b, nm, indent) };
            // SAFETY: made above.
            unsafe { crate::bio::BIO_free(b) };
            return r;
        }
        let mut write = |chunk: &[u8]| {
            // SAFETY: the caller's `FILE`; the chunk.
            (unsafe { libc::fwrite(chunk.as_ptr().cast(), 1, chunk.len(), fp) }) == chunk.len()
        };
        // SAFETY: the caller's guarantee.
        unsafe { name_ex(&mut write, nm, indent.max(0), flags) }
    }
}
