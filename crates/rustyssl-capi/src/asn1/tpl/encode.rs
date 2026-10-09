//! Encoding values by their items (`ASN1_item_i2d(3)`, `ASN1_item_ex_i2d`,
//! `ASN1_item_ndef_i2d`), as OpenSSL's `tasn_enc.c` does: every element is sized first, then
//! written, so items and aux callbacks run in both passes (`ASN1_OP_I2D_PRE`/`_POST`), and a
//! SET OF is encoded to a scratch buffer and written in DER order.
//!
//! Output goes through a cursor. When rustyssl allocates the buffer it knows its size, and a
//! write past it (an application's callback answering differently in the two passes) is dropped
//! and the encoding fails, where OpenSSL would overrun the heap (docs/DEVIATIONS.md). A buffer
//! the caller passes has no known size and is written as in C.

use core::ffi::{c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_AFLG_CONST_CB, ASN1_AUX, ASN1_ENCODING, ASN1_EXTERN_FUNCS, ASN1_ITEM, ASN1_ITYPE_CHOICE,
    ASN1_ITYPE_EXTERN, ASN1_ITYPE_MSTRING, ASN1_ITYPE_NDEF_SEQUENCE, ASN1_ITYPE_PRIMITIVE,
    ASN1_ITYPE_SEQUENCE, ASN1_OBJECT, ASN1_OP_I2D_POST, ASN1_OP_I2D_PRE, ASN1_PRIMITIVE_FUNCS,
    ASN1_R_BAD_TEMPLATE, ASN1_R_ILLEGAL_ZERO_CONTENT, ASN1_STRING, ASN1_STRING_FLAG_NDEF,
    ASN1_TEMPLATE, ASN1_TFLG_EMBED, ASN1_TFLG_EXPTAG, ASN1_TFLG_NDEF, ASN1_TFLG_OPTIONAL,
    ASN1_TFLG_SEQUENCE_OF, ASN1_TFLG_SET_OF, ASN1_TFLG_SK_MASK, ASN1_TFLG_TAG_CLASS,
    ASN1_TFLG_TAG_MASK, ASN1_TYPE, ASN1_VALUE, ERR_LIB_ASN1, ERR_R_INTERNAL_ERROR, OPENSSL_STACK,
    V_ASN1_ANY, V_ASN1_BIT_STRING, V_ASN1_BOOLEAN, V_ASN1_ENUMERATED, V_ASN1_INTEGER, V_ASN1_NULL,
    V_ASN1_OBJECT, V_ASN1_OTHER, V_ASN1_SEQUENCE, V_ASN1_SET, V_ASN1_UNDEF, V_ASN1_UNIVERSAL,
};
use rustyssl_asn1::der;
use rustyssl_asn1::text::{bit_string_content, integer_content};

use super::{
    aux, choice_selector, field_ptr, itype, long_to_int, template_flags, template_item, utype,
};
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::Object;
use crate::stack;

/// A value's slot for reading: `const ASN1_VALUE **`.
type Cpval = *mut *const ASN1_VALUE;

/// Where an encoding goes: `unsigned char *` with, when known, where the buffer ends.
pub(crate) struct Out {
    /// The next octet to write (`*out` in C).
    pub(crate) p: *mut c_uchar,
    /// The buffer's end, or NULL if unknown.
    end: *mut c_uchar,
    /// Whether a write was dropped for want of room.
    overflow: bool,
}

impl Out {
    /// A cursor with no known end.
    pub(crate) fn unbounded(p: *mut c_uchar) -> Self {
        Self {
            p,
            end: ptr::null_mut(),
            overflow: false,
        }
    }

    /// A cursor over `len` octets at `p`.
    fn bounded(p: *mut c_uchar, len: usize) -> Self {
        Self {
            p,
            end: p.wrapping_add(len),
            overflow: false,
        }
    }

    /// Whether `n` more octets fit; if not, notes the overflow.
    fn room(&mut self, n: usize) -> bool {
        if self.end.is_null() || (self.end as usize).wrapping_sub(self.p as usize) >= n {
            return true;
        }
        self.overflow = true;
        false
    }

    /// Notes an overflow by a callback that moved the cursor past the end.
    fn check(&mut self) {
        if !self.end.is_null() && self.p > self.end {
            self.overflow = true;
        }
    }

    /// Writes `bytes` and moves past them.
    ///
    /// # Safety
    /// Without a known end, the caller's buffer has room for them.
    unsafe fn put(&mut self, bytes: &[u8]) {
        if !self.room(bytes.len()) {
            return;
        }
        // SAFETY: room checked, or the caller's guarantee.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), self.p, bytes.len()) };
        self.p = self.p.wrapping_add(bytes.len());
    }

    /// `ASN1_put_object`.
    ///
    /// # Safety
    /// As for [`Out::put`].
    unsafe fn put_object(&mut self, constructed: c_int, length: c_int, tag: c_int, class: c_int) {
        let mut header = Vec::new();
        der::put_header(&mut header, constructed, length, tag, class);
        // SAFETY: the caller's guarantee.
        unsafe { self.put(&header) };
    }

    /// `ASN1_put_eoc`.
    ///
    /// # Safety
    /// As for [`Out::put`].
    unsafe fn put_eoc(&mut self) {
        // SAFETY: the caller's guarantee.
        unsafe { self.put(&[0, 0]) };
    }
}

/// An aux callback, as `ASN1_item_ex_i2d` picks it: the const one with `ASN1_AFLG_CONST_CB`,
/// else the other.
#[derive(Clone, Copy)]
enum Callback {
    Const(
        unsafe extern "C" fn(c_int, *mut *const ASN1_VALUE, *const ASN1_ITEM, *mut c_void) -> c_int,
    ),
    Mut(unsafe extern "C" fn(c_int, *mut *mut ASN1_VALUE, *const ASN1_ITEM, *mut c_void) -> c_int),
}

impl Callback {
    /// The callback of an item whose funcs are aux data, if any.
    ///
    /// # Safety
    /// `aux` is NULL or live aux data.
    unsafe fn of(aux: *const ASN1_AUX) -> Option<Self> {
        if aux.is_null() {
            return None;
        }
        // SAFETY: the caller's guarantee.
        let aux = unsafe { &*aux };
        if aux.flags & ASN1_AFLG_CONST_CB != 0 {
            aux.asn1_const_cb.map(Self::Const)
        } else {
            aux.asn1_cb.map(Self::Mut)
        }
    }

    /// Calls it for `op`.
    ///
    /// # Safety
    /// The application's callback, called with a live value of `it`.
    unsafe fn call(self, op: c_int, pval: Cpval, it: *const ASN1_ITEM) -> c_int {
        match self {
            // SAFETY: the caller's guarantee.
            Self::Const(cb) => unsafe { cb(op, pval, it, ptr::null_mut()) },
            // SAFETY: as above; the callback may not change the value, as in OpenSSL.
            Self::Mut(cb) => unsafe { cb(op, pval.cast(), it, ptr::null_mut()) },
        }
    }
}

/// `asn1_item_flags_i2d`: encodes `val` into `*out` (moving it on), into a new buffer stored in
/// `*out` if that's NULL, or only measures it if `out` is NULL. Returns the length, or <= 0.
///
/// # Safety
/// `val` is a live value of `it`, a live item whose tables and functions can be trusted; `out`
/// is NULL or valid for reads and writes, and a non-NULL `*out` has room for the encoding.
unsafe fn flags_i2d(
    val: *const ASN1_VALUE,
    out: *mut *mut c_uchar,
    it: *const ASN1_ITEM,
    flags: c_int,
) -> c_int {
    let mut val = val;
    // SAFETY: the caller's guarantee.
    if !out.is_null() && unsafe { out.read() }.is_null() {
        // SAFETY: the caller's guarantee, with a local slot.
        let len = unsafe { item_ex_i2d(&raw mut val, None, it, -1, flags) };
        if len <= 0 {
            return len;
        }
        let size = usize::try_from(len).unwrap_or(0);
        let buf: *mut c_uchar = mem::alloc_zeroed(size).cast();
        if buf.is_null() {
            return -1;
        }
        let mut cursor = Out::bounded(buf, size);
        // SAFETY: as above, into a buffer of the measured length.
        unsafe { item_ex_i2d(&raw mut val, Some(&mut cursor), it, -1, flags) };
        if cursor.overflow {
            // SAFETY: the buffer just allocated.
            unsafe { mem::release(buf.cast()) };
            err::raise(ERR_LIB_ASN1, ERR_R_INTERNAL_ERROR, "asn1_item_flags_i2d");
            return -1;
        }
        // SAFETY: the caller's slot.
        unsafe { out.write(buf) };
        return len;
    }
    // SAFETY: the caller's guarantee.
    unsafe { ex_i2d_raw(&raw mut val, out, it, -1, flags) }
}

/// `ASN1_item_ex_i2d` on C's `unsigned char **`.
///
/// # Safety
/// As for [`item_ex_i2d`], with `out` NULL or a valid slot whose buffer has room.
pub(crate) unsafe fn ex_i2d_raw(
    pval: Cpval,
    out: *mut *mut c_uchar,
    it: *const ASN1_ITEM,
    tag: c_int,
    aclass: c_int,
) -> c_int {
    if out.is_null() {
        // SAFETY: the caller's guarantee.
        return unsafe { item_ex_i2d(pval, None, it, tag, aclass) };
    }
    // SAFETY: the caller's slot.
    let mut cursor = Out::unbounded(unsafe { out.read() });
    // SAFETY: the caller's guarantee.
    let ret = unsafe { item_ex_i2d(pval, Some(&mut cursor), it, tag, aclass) };
    // SAFETY: as above.
    unsafe { out.write(cursor.p) };
    ret
}

/// Calls an item function taking `unsigned char **` with the cursor.
///
/// # Safety
/// `f` writes only within the cursor's buffer.
unsafe fn through(out: Option<&mut Out>, f: impl FnOnce(*mut *mut c_uchar) -> c_int) -> c_int {
    match out {
        None => f(ptr::null_mut()),
        Some(cursor) => {
            let ret = f(&raw mut cursor.p);
            cursor.check();
            ret
        }
    }
}

/// `ASN1_item_ex_i2d`: the length of the encoding of the value of `it` in `*pval`, with
/// implicit tag `tag` (or -1) and class (and `ASN1_TFLG_NDEF`) `aclass`, writing it to `out`
/// if given. 0 for an absent value, -1 on error.
///
/// # Safety
/// `pval` holds NULL or a live value of `it` (a BOOLEAN's slot is its `int`); `it` is a live
/// item whose tables and functions can be trusted; an unbounded `out` has room.
pub(crate) unsafe fn item_ex_i2d(
    pval: Cpval,
    out: Option<&mut Out>,
    it: *const ASN1_ITEM,
    tag: c_int,
    aclass: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let kind = unsafe { itype(it) };
    // SAFETY: as above.
    if kind != ASN1_ITYPE_PRIMITIVE && unsafe { pval.read() }.is_null() {
        return 0;
    }
    // SAFETY: as above.
    let item = unsafe { &*it };
    let callback = match kind {
        ASN1_ITYPE_CHOICE | ASN1_ITYPE_SEQUENCE | ASN1_ITYPE_NDEF_SEQUENCE => {
            // SAFETY: these items' funcs are aux data.
            let aux = unsafe { aux(it) };
            // SAFETY: as above.
            unsafe { Callback::of(aux) }
        }
        _ => None,
    };
    let mut tag = tag;
    let mut aclass = aclass;
    match kind {
        ASN1_ITYPE_PRIMITIVE => {
            if !item.templates.is_null() {
                // SAFETY: the item's template.
                return unsafe { template_ex_i2d(pval, out, item.templates, tag, aclass) };
            }
            // SAFETY: the caller's guarantee.
            unsafe { i2d_ex_primitive(pval, out, it, tag, aclass) }
        }
        ASN1_ITYPE_MSTRING => {
            if tag != -1 {
                err::raise(ERR_LIB_ASN1, ASN1_R_BAD_TEMPLATE, "ASN1_item_ex_i2d");
                return -1;
            }
            // SAFETY: the caller's guarantee.
            unsafe { i2d_ex_primitive(pval, out, it, -1, aclass) }
        }
        ASN1_ITYPE_CHOICE => {
            if tag != -1 {
                err::raise(ERR_LIB_ASN1, ASN1_R_BAD_TEMPLATE, "ASN1_item_ex_i2d");
                return -1;
            }
            if let Some(cb) = callback {
                // SAFETY: the application's callback.
                if unsafe { cb.call(ASN1_OP_I2D_PRE, pval, it) } == 0 {
                    return 0;
                }
            }
            // SAFETY: a live CHOICE structure.
            let i = unsafe { choice_selector(pval.cast(), it) };
            if let Ok(index) = usize::try_from(i)
                && core::ffi::c_long::from(i) < item.tcount
            {
                let chtt = item.templates.wrapping_add(index);
                // SAFETY: a template of the item, for a field of the structure.
                let pchval = unsafe { field_ptr(pval.cast(), chtt) };
                // SAFETY: as above.
                return unsafe { template_ex_i2d(pchval.cast(), out, chtt, -1, aclass) };
            }
            if let Some(cb) = callback {
                // SAFETY: as above.
                if unsafe { cb.call(ASN1_OP_I2D_POST, pval, it) } == 0 {
                    return 0;
                }
            }
            0
        }
        ASN1_ITYPE_EXTERN => {
            // SAFETY: an extern item's funcs; OpenSSL calls its i2d unchecked.
            let ef = unsafe { super::funcs::<ASN1_EXTERN_FUNCS>(it) };
            let Some(i2d) = ef.and_then(|ef| ef.asn1_ex_i2d) else {
                return 0;
            };
            // SAFETY: the item's own function, writing within the buffer.
            let write = |o| unsafe { i2d(pval, o, it, tag, aclass) };
            // SAFETY: as above.
            unsafe { through(out, write) }
        }
        ASN1_ITYPE_NDEF_SEQUENCE | ASN1_ITYPE_SEQUENCE => {
            let ndef = if kind == ASN1_ITYPE_NDEF_SEQUENCE && aclass & ASN1_TFLG_NDEF != 0 {
                2
            } else {
                1
            };
            // SAFETY: a live SEQUENCE structure.
            let enc: *const ASN1_ENCODING = unsafe { super::enc_ptr(pval.cast(), it) };
            // SAFETY: a live cache.
            if !enc.is_null() && unsafe { (*enc).modified } == 0 {
                // SAFETY: as above.
                let cache = unsafe { &*enc };
                let (data, len) = (cache.enc, cache.len);
                if let Some(cursor) = out {
                    let n = usize::try_from(len).unwrap_or(0);
                    // SAFETY: the cached encoding holds its length.
                    let bytes = unsafe { core::slice::from_raw_parts(data, n) };
                    // SAFETY: the caller's guarantee.
                    unsafe { cursor.put(bytes) };
                }
                return long_to_int(len);
            }
            if tag == -1 {
                tag = V_ASN1_SEQUENCE;
                aclass = (aclass & !ASN1_TFLG_TAG_CLASS) | V_ASN1_UNIVERSAL;
            }
            if let Some(cb) = callback {
                // SAFETY: the application's callback.
                if unsafe { cb.call(ASN1_OP_I2D_PRE, pval, it) } == 0 {
                    return 0;
                }
            }
            let count = usize::try_from(item.tcount).unwrap_or(0);
            let mut seqcontlen: c_int = 0;
            for i in 0..count {
                let tt = item.templates.wrapping_add(i);
                // SAFETY: the caller's slot.
                let structure = unsafe { pval.read() };
                // SAFETY: the structure and a template of the item.
                let seqtt = unsafe { super::do_adb(structure, tt, true) };
                if seqtt.is_null() {
                    return 0;
                }
                // SAFETY: as above.
                let pseqval = unsafe { field_ptr(pval.cast(), seqtt) };
                // SAFETY: as above.
                let tmplen = unsafe { template_ex_i2d(pseqval.cast(), None, seqtt, -1, aclass) };
                if tmplen == -1 || tmplen > c_int::MAX.wrapping_sub(seqcontlen) {
                    return -1;
                }
                seqcontlen = seqcontlen.wrapping_add(tmplen);
            }
            let seqlen = der::object_size(ndef, seqcontlen, tag);
            let Some(cursor) = out else {
                return seqlen;
            };
            if seqlen == -1 {
                return seqlen;
            }
            // SAFETY: the caller's guarantee.
            unsafe { cursor.put_object(ndef, seqcontlen, tag, aclass) };
            for i in 0..count {
                let tt = item.templates.wrapping_add(i);
                // SAFETY: as above.
                let structure = unsafe { pval.read() };
                // SAFETY: as above.
                let seqtt = unsafe { super::do_adb(structure, tt, true) };
                if seqtt.is_null() {
                    return 0;
                }
                // SAFETY: as above.
                let pseqval = unsafe { field_ptr(pval.cast(), seqtt) };
                // SAFETY: as above.
                unsafe { template_ex_i2d(pseqval.cast(), Some(&mut *cursor), seqtt, -1, aclass) };
            }
            if ndef == 2 {
                // SAFETY: as above.
                unsafe { cursor.put_eoc() };
            }
            if let Some(cb) = callback {
                // SAFETY: as above.
                if unsafe { cb.call(ASN1_OP_I2D_POST, pval, it) } == 0 {
                    return 0;
                }
            }
            seqlen
        }
        _ => 0,
    }
}

/// `asn1_template_ex_i2d`: a template's field, with its own tagging or the caller's.
///
/// # Safety
/// `pval` is the field's slot (or the field, if embedded); `tt` is a live template; an
/// unbounded `out` has room.
unsafe fn template_ex_i2d(
    pval: Cpval,
    mut out: Option<&mut Out>,
    tt: *const ASN1_TEMPLATE,
    tag: c_int,
    iclass: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let flags = unsafe { template_flags(tt) };
    // SAFETY: as above.
    let it = unsafe { template_item(tt) };
    let mut tval: *const ASN1_VALUE = pval.cast_const().cast();
    let pval = if flags & ASN1_TFLG_EMBED != 0 {
        &raw mut tval
    } else {
        pval
    };
    let (ttag, tclass) = if flags & ASN1_TFLG_TAG_MASK != 0 {
        if tag != -1 {
            return -1;
        }
        // SAFETY: as above.
        (
            long_to_int(unsafe { (*tt).tag }),
            flags & ASN1_TFLG_TAG_CLASS,
        )
    } else if tag != -1 {
        (tag, iclass & ASN1_TFLG_TAG_CLASS)
    } else {
        (-1, 0)
    };
    let iclass = iclass & !ASN1_TFLG_TAG_CLASS;
    let ndef = if flags & ASN1_TFLG_NDEF != 0 && iclass & ASN1_TFLG_NDEF != 0 {
        2
    } else {
        1
    };

    if flags & ASN1_TFLG_SK_MASK != 0 {
        // SAFETY: the field's slot holds a stack, or NULL.
        let sk: *mut OPENSSL_STACK = unsafe { pval.read() }.cast_mut().cast();
        if sk.is_null() {
            return 0;
        }
        let isset = if flags & ASN1_TFLG_SET_OF == 0 {
            0
        } else if flags & ASN1_TFLG_SEQUENCE_OF != 0 {
            2
        } else {
            1
        };
        let (sktag, skaclass) = if ttag != -1 && flags & ASN1_TFLG_EXPTAG == 0 {
            (ttag, tclass)
        } else {
            (
                if isset != 0 {
                    V_ASN1_SET
                } else {
                    V_ASN1_SEQUENCE
                },
                V_ASN1_UNIVERSAL,
            )
        };
        let mut skcontlen: c_int = 0;
        let mut i = 0;
        // SAFETY: a live stack.
        while i < unsafe { stack::OPENSSL_sk_num(sk) } {
            // SAFETY: as above.
            let mut skitem: *const ASN1_VALUE = unsafe { stack::OPENSSL_sk_value(sk, i) }.cast();
            // SAFETY: an element, a value of the item.
            let len = unsafe { item_ex_i2d(&raw mut skitem, None, it, -1, iclass) };
            if len == -1 || skcontlen > c_int::MAX.wrapping_sub(len) {
                return -1;
            }
            if len == 0 && flags & ASN1_TFLG_OPTIONAL == 0 {
                err::raise(
                    ERR_LIB_ASN1,
                    ASN1_R_ILLEGAL_ZERO_CONTENT,
                    "asn1_template_ex_i2d",
                );
                return -1;
            }
            skcontlen = skcontlen.wrapping_add(len);
            i = i.wrapping_add(1);
        }
        let sklen = der::object_size(ndef, skcontlen, sktag);
        if sklen == -1 {
            return -1;
        }
        let ret = if flags & ASN1_TFLG_EXPTAG != 0 {
            der::object_size(ndef, sklen, ttag)
        } else {
            sklen
        };
        let Some(cursor) = out.as_deref_mut() else {
            return ret;
        };
        if ret == -1 {
            return ret;
        }
        if flags & ASN1_TFLG_EXPTAG != 0 {
            // SAFETY: the caller's guarantee.
            unsafe { cursor.put_object(ndef, sklen, ttag, tclass) };
        }
        // SAFETY: as above.
        unsafe { cursor.put_object(ndef, skcontlen, sktag, skaclass) };
        // SAFETY: as above.
        unsafe { set_seq_out(sk, cursor, skcontlen, it, isset, iclass) };
        if ndef == 2 {
            // SAFETY: as above.
            unsafe { cursor.put_eoc() };
            if flags & ASN1_TFLG_EXPTAG != 0 {
                // SAFETY: as above.
                unsafe { cursor.put_eoc() };
            }
        }
        return ret;
    }

    if flags & ASN1_TFLG_EXPTAG != 0 {
        // SAFETY: the caller's guarantee.
        let i = unsafe { item_ex_i2d(pval, None, it, -1, iclass) };
        if i == 0 {
            if flags & ASN1_TFLG_OPTIONAL == 0 {
                err::raise(
                    ERR_LIB_ASN1,
                    ASN1_R_ILLEGAL_ZERO_CONTENT,
                    "asn1_template_ex_i2d",
                );
                return -1;
            }
            return 0;
        }
        let ret = der::object_size(ndef, i, ttag);
        if let Some(cursor) = out
            && ret != -1
        {
            // SAFETY: as above.
            unsafe { cursor.put_object(ndef, i, ttag, tclass) };
            // SAFETY: as above.
            unsafe { item_ex_i2d(pval, Some(&mut *cursor), it, -1, iclass) };
            if ndef == 2 {
                // SAFETY: as above.
                unsafe { cursor.put_eoc() };
            }
        }
        return ret;
    }

    // SAFETY: the caller's guarantee.
    let len = unsafe { item_ex_i2d(pval, out, it, ttag, tclass | iclass) };
    if len == 0 && flags & ASN1_TFLG_OPTIONAL == 0 {
        err::raise(
            ERR_LIB_ASN1,
            ASN1_R_ILLEGAL_ZERO_CONTENT,
            "asn1_template_ex_i2d",
        );
        return -1;
    }
    len
}

/// `asn1_set_seq_out`: a SET OF or SEQUENCE OF's elements, in DER order for a SET OF of two or
/// more (reordering the stack too for `ASN1_TFLG_SET_ORDER`).
///
/// # Safety
/// `sk` is a live stack of values of `item`; an unbounded `out` has room for `skcontlen`.
unsafe fn set_seq_out(
    sk: *mut OPENSSL_STACK,
    out: &mut Out,
    skcontlen: c_int,
    item: *const ASN1_ITEM,
    do_sort: c_int,
    iclass: c_int,
) {
    // SAFETY: the caller's guarantee.
    let count = unsafe { stack::OPENSSL_sk_num(sk) };
    if do_sort == 0 || count < 2 {
        for i in 0..count {
            // SAFETY: as above.
            let mut skitem: *const ASN1_VALUE = unsafe { stack::OPENSSL_sk_value(sk, i) }.cast();
            // SAFETY: an element, a value of the item.
            unsafe { item_ex_i2d(&raw mut skitem, Some(&mut *out), item, -1, iclass) };
        }
        return;
    }
    let size = usize::try_from(skcontlen).unwrap_or(0);
    let mut scratch = vec![0u8; size];
    let mut cursor = Out::bounded(scratch.as_mut_ptr(), size);
    // Each element's offset into the scratch buffer, length, and value.
    let mut encodings: Vec<(usize, usize, *const ASN1_VALUE)> = Vec::new();
    for i in 0..count {
        // SAFETY: as above.
        let mut skitem: *const ASN1_VALUE = unsafe { stack::OPENSSL_sk_value(sk, i) }.cast();
        let start = (cursor.p as usize).wrapping_sub(scratch.as_ptr() as usize);
        // SAFETY: as above, into the scratch buffer.
        let len = unsafe { item_ex_i2d(&raw mut skitem, Some(&mut cursor), item, -1, iclass) };
        let len = usize::try_from(len).unwrap_or(0);
        encodings.push((start, len, skitem));
    }
    if cursor.overflow {
        out.overflow = true;
        return;
    }
    let bytes = |&(start, len, _): &(usize, usize, *const ASN1_VALUE)| -> &[u8] {
        scratch.get(start..start.saturating_add(len)).unwrap_or(&[])
    };
    encodings.sort_by(|a, b| bytes(a).cmp(bytes(b)));
    for encoding in &encodings {
        // SAFETY: the caller's guarantee.
        unsafe { out.put(bytes(encoding)) };
    }
    if do_sort == 2 {
        for (i, &(_, _, field)) in (0..).zip(&encodings) {
            // SAFETY: a live stack, reordered.
            unsafe { stack::OPENSSL_sk_set(sk, i, field.cast()) };
        }
    }
}

/// `asn1_i2d_ex_primitive`: a primitive's header and content.
///
/// # Safety
/// As for [`item_ex_i2d`], for a primitive or MSTRING item.
unsafe fn i2d_ex_primitive(
    pval: Cpval,
    out: Option<&mut Out>,
    it: *const ASN1_ITEM,
    tag: c_int,
    aclass: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let mut kind = unsafe { utype(it) };
    // SAFETY: as above.
    let mut len = unsafe { ex_i2c(pval, ptr::null_mut(), &mut kind, it) };
    let usetag = !(kind == V_ASN1_SEQUENCE || kind == V_ASN1_SET || kind == V_ASN1_OTHER);
    if len == -1 {
        return 0;
    }
    let mut ndef = 0;
    if len == -2 {
        ndef = 2;
        len = 0;
    }
    let tag = if tag == -1 { kind } else { tag };
    if let Some(cursor) = out {
        if usetag {
            // SAFETY: the caller's guarantee.
            unsafe { cursor.put_object(ndef, len, tag, aclass) };
        }
        let n = usize::try_from(len).unwrap_or(0);
        if cursor.room(n) {
            // SAFETY: as above, with room for the content.
            unsafe { ex_i2c(pval, cursor.p, &mut kind, it) };
            if ndef != 0 {
                // SAFETY: as above.
                unsafe { cursor.put_eoc() };
            } else {
                cursor.p = cursor.p.wrapping_add(n);
            }
        }
    }
    if usetag {
        der::object_size(ndef, len, tag)
    } else {
        len
    }
}

/// `asn1_ex_i2c`: a primitive's content octets (written to `cout` if not NULL) and length; -1
/// to omit it, -2 for the indefinite length. Sets `*putype` to an MSTRING's or ANY's type.
///
/// # Safety
/// As for [`item_ex_i2d`]; `cout` is NULL or has room for the content.
unsafe fn ex_i2c(
    pval: Cpval,
    cout: *mut c_uchar,
    putype: &mut c_int,
    it: *const ASN1_ITEM,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let item = unsafe { &*it };
    // SAFETY: a primitive item's funcs.
    let pf = unsafe { super::funcs::<ASN1_PRIMITIVE_FUNCS>(it) };
    if let Some(i2c) = pf.and_then(|pf| pf.prim_i2c) {
        // SAFETY: the item's own function.
        return unsafe { i2c(pval, cout, putype, it) };
    }
    // SAFETY: the caller's guarantee.
    let (kind, item_utype) = (unsafe { itype(it) }, unsafe { utype(it) });
    // SAFETY: the caller's slot.
    let absent = unsafe { pval.read() }.is_null();
    if (kind != ASN1_ITYPE_PRIMITIVE || item_utype != V_ASN1_BOOLEAN) && absent {
        return -1;
    }
    let mut pval = pval;
    let utype = if kind == ASN1_ITYPE_MSTRING {
        // SAFETY: the caller's slot.
        let str: *const ASN1_STRING = unsafe { pval.read() }.cast();
        // SAFETY: an MSTRING's value is a string.
        let t = unsafe { (*str).type_ };
        *putype = t;
        t
    } else if item_utype == V_ASN1_ANY {
        // SAFETY: the caller's slot.
        let typ: *const ASN1_TYPE = unsafe { pval.read() }.cast();
        // SAFETY: an ANY's value is an ASN1_TYPE.
        let t = unsafe { (*typ).type_ };
        *putype = t;
        // Its value's slot is the union (a BOOLEAN's `int`, or a pointer).
        // SAFETY: as above.
        pval = unsafe { (&raw const (*typ).value).cast_mut().cast() };
        t
    } else {
        *putype
    };
    // SAFETY: the value in the slot.
    let value = unsafe { pval.read() };
    if value.is_null() && !matches!(utype, V_ASN1_UNDEF | V_ASN1_NULL | V_ASN1_BOOLEAN) {
        // An ANY holding no value: omitted, where OpenSSL dereferences NULL.
        return -1;
    }
    let content: Vec<u8> = match utype {
        V_ASN1_OBJECT => {
            let object: *const Object = value.cast::<ASN1_OBJECT>().cast();
            // SAFETY: an OBJECT's value is an object.
            let object = unsafe { &*object };
            let (data, length) = (object.data, object.length);
            if data.is_null() || length == 0 {
                return -1;
            }
            // SAFETY: an object's data holds its length.
            unsafe { core::slice::from_raw_parts(data, usize::try_from(length).unwrap_or(0)) }
                .to_vec()
        }
        V_ASN1_UNDEF => return -2,
        V_ASN1_NULL => Vec::new(),
        V_ASN1_BOOLEAN => {
            // SAFETY: a BOOLEAN's slot is its `int`.
            let tbool = unsafe { pval.cast::<c_int>().read() };
            if tbool == -1 {
                return -1;
            }
            if item_utype != V_ASN1_ANY {
                if tbool != 0 && item.size > 0 {
                    return -1;
                }
                if tbool == 0 && item.size == 0 {
                    return -1;
                }
            }
            vec![tbool.to_le_bytes()[0]]
        }
        V_ASN1_BIT_STRING | V_ASN1_INTEGER | V_ASN1_ENUMERATED => {
            // SAFETY: the value is a string.
            let str = unsafe { &*value.cast::<ASN1_STRING>() };
            // SAFETY: a string's data holds its length.
            let octets = unsafe { string_octets(str) };
            if utype == V_ASN1_BIT_STRING {
                if str.length < 0 {
                    // C's `1 + len` with no octets written past the unused-bits one.
                    let ret = str.length.wrapping_add(1);
                    if !cout.is_null() {
                        // SAFETY: the caller's guarantee.
                        unsafe { cout.write(0) };
                    }
                    return ret;
                }
                bit_string_content(octets, str.flags)
            } else {
                integer_content(octets, str.type_ & rustyssl_abi::V_ASN1_NEG != 0)
            }
        }
        _ => {
            let str: *mut ASN1_STRING = value.cast_mut().cast();
            // SAFETY: any other value is a string.
            let s = unsafe { &mut *str };
            if item.size == ASN1_TFLG_NDEF.into()
                && s.flags & core::ffi::c_long::from(ASN1_STRING_FLAG_NDEF) != 0
            {
                if !cout.is_null() {
                    s.data = cout;
                    s.length = 0;
                }
                return -2;
            }
            if !cout.is_null() && s.length != 0 && !s.data.is_null() {
                let n = usize::try_from(s.length).unwrap_or(0);
                // SAFETY: the string holds its length; the caller's room.
                unsafe { ptr::copy_nonoverlapping(s.data, cout, n) };
            }
            return s.length;
        }
    };
    if !cout.is_null() && !content.is_empty() {
        // SAFETY: the caller's guarantee.
        unsafe { ptr::copy_nonoverlapping(content.as_ptr(), cout, content.len()) };
    }
    c_int::try_from(content.len()).unwrap_or(c_int::MAX)
}

/// A string's octets: none for NULL data or a negative length.
///
/// # Safety
/// `a`'s data holds its length.
unsafe fn string_octets<'a>(a: &ASN1_STRING) -> &'a [u8] {
    match usize::try_from(a.length) {
        // SAFETY: the caller's guarantee.
        Ok(n) if !a.data.is_null() => unsafe { core::slice::from_raw_parts(a.data, n) },
        _ => &[],
    }
}

ffi_export! {
    /// Encodes `val`, a value of `it`, as DER: into `*out` (moving it past the encoding), into
    /// a new buffer stored in `*out` if that's NULL, or only measuring if `out` is NULL.
    /// Returns the length, or <= 0 on error.
    ///
    /// # Safety
    /// `val` is NULL or a live value of `it`, a live item whose tables and functions can be
    /// trusted; `out` is NULL or valid for reads and writes, and a non-NULL `*out` has room.
    pub unsafe extern "C" fn ASN1_item_i2d(val: *const ASN1_VALUE, out: *mut *mut c_uchar, it: *const ASN1_ITEM) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { flags_i2d(val, out, it, 0) }
    }
}

ffi_export! {
    /// `ASN1_item_i2d`, with the indefinite length for NDEF SEQUENCEs and streamed strings.
    ///
    /// # Safety
    /// As for `ASN1_item_i2d`.
    pub unsafe extern "C" fn ASN1_item_ndef_i2d(val: *const ASN1_VALUE, out: *mut *mut c_uchar, it: *const ASN1_ITEM) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { flags_i2d(val, out, it, ASN1_TFLG_NDEF) }
    }
}

ffi_export! {
    /// Encodes the value of `it` in `*pval` with implicit tag `tag` (-1 for none) and class
    /// `aclass`, into `*out` (moving it on) or, with `out` NULL, only measuring. Returns the
    /// length, 0 for an absent value, or -1.
    ///
    /// # Safety
    /// `pval` is valid for a read and holds NULL or a live value of `it`; otherwise as for
    /// `ASN1_item_i2d`, except that NULL `*out` isn't allocated.
    pub unsafe extern "C" fn ASN1_item_ex_i2d(pval: *mut *const ASN1_VALUE, out: *mut *mut c_uchar, it: *const ASN1_ITEM, tag: c_int, aclass: c_int) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ex_i2d_raw(pval, out, it, tag, aclass) }
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use rustyssl_abi::{
        ASN1_ITYPE_SEQUENCE, ASN1_OP_I2D_PRE, ASN1_R_ILLEGAL_ZERO_CONTENT, V_ASN1_OCTET_STRING,
    };

    use super::*;
    use crate::asn1::string;
    use crate::asn1::tpl::free::ASN1_item_free;
    use crate::asn1::tpl::items::{ASN1_ANY_it, ASN1_OCTET_STRING_it};
    use crate::asn1::tpl::new::ASN1_item_new;
    use crate::asn1::tpl::{Item, Template, item, size_of_long, template};

    /// A SEQUENCE holding one OCTET STRING, which its callback lengthens on the second
    /// `ASN1_OP_I2D_PRE`: between the pass that sizes the encoding and the one that writes it.
    #[repr(C)]
    struct Growing {
        octets: *mut ASN1_STRING,
    }

    static PRE_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn grow(
        operation: c_int,
        pval: *mut *mut ASN1_VALUE,
        _it: *const ASN1_ITEM,
        _exarg: *mut c_void,
    ) -> c_int {
        if operation == ASN1_OP_I2D_PRE && PRE_CALLS.fetch_add(1, Ordering::Relaxed) == 1 {
            // SAFETY: the callback's slot.
            let value = unsafe { pval.read() };
            // SAFETY: a live `Growing`.
            let growing = unsafe { &*value.cast::<Growing>() };
            // SAFETY: its string.
            unsafe { string::set(growing.octets, c"a much longer value".as_ptr().cast(), -1) };
        }
        1
    }

    struct Aux(ASN1_AUX);
    // SAFETY: immutable, with no pointers but the callback.
    unsafe impl Sync for Aux {}

    static GROWING_AUX: Aux = Aux(ASN1_AUX {
        app_data: ptr::null_mut(),
        flags: 0,
        ref_offset: 0,
        ref_lock: 0,
        asn1_cb: Some(grow),
        enc_offset: 0,
        asn1_const_cb: None,
    });
    static GROWING_TT: Template = template(0, 0, c"octets", ASN1_OCTET_STRING_it);
    static GROWING: Item = item(
        ASN1_ITYPE_SEQUENCE,
        V_ASN1_SEQUENCE,
        &raw const GROWING_TT.0,
        1,
        (&raw const GROWING_AUX.0).cast(),
        size_of_long::<Growing>(),
        c"GROWING",
    );

    #[test]
    fn a_callback_cannot_overrun_the_buffer() {
        // SAFETY: a live item.
        let value = unsafe { ASN1_item_new(&raw const GROWING.0) };
        assert!(!value.is_null());
        let mut out: *mut c_uchar = ptr::null_mut();
        // SAFETY: a live value of the item.
        let len = unsafe { ASN1_item_i2d(value, &raw mut out, &raw const GROWING.0) };
        assert_eq!(len, -1);
        assert!(out.is_null());
        // SAFETY: no preconditions.
        let code = unsafe { crate::err::ERR_get_error() };
        assert_eq!(crate::err::library_of(code), ERR_LIB_ASN1);
        // SAFETY: the value made above.
        unsafe { ASN1_item_free(value, &raw const GROWING.0) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }

    #[test]
    fn an_any_without_a_value_is_left_out() {
        // SAFETY: no preconditions.
        let it = unsafe { ASN1_ANY_it() };
        // SAFETY: the ANY item.
        let any: *mut ASN1_TYPE = unsafe { ASN1_item_new(it) }.cast();
        // SAFETY: a new ASN1_TYPE.
        unsafe { (*any).type_ = V_ASN1_OCTET_STRING };
        // SAFETY: as above.
        let len = unsafe { ASN1_item_i2d(any.cast(), ptr::null_mut(), it) };
        assert_eq!(len, 0);
        // SAFETY: as above.
        unsafe { ASN1_item_free(any.cast(), it) };
    }

    /// `Growing` without the callback.
    static PLAIN: Item = item(
        ASN1_ITYPE_SEQUENCE,
        V_ASN1_SEQUENCE,
        &raw const GROWING_TT.0,
        1,
        ptr::null(),
        size_of_long::<Growing>(),
        c"PLAIN",
    );

    #[test]
    fn a_required_field_must_be_present() {
        // SAFETY: a live item.
        let value = unsafe { ASN1_item_new(&raw const PLAIN.0) };
        // SAFETY: the `Growing` made above.
        let growing = unsafe { &mut *value.cast::<Growing>() };
        // SAFETY: its string.
        unsafe { string::ASN1_STRING_free(growing.octets) };
        growing.octets = ptr::null_mut();
        // SAFETY: as above.
        let len = unsafe { ASN1_item_i2d(value, ptr::null_mut(), &raw const PLAIN.0) };
        assert_eq!(len, -1);
        // SAFETY: no preconditions.
        let code = unsafe { crate::err::ERR_get_error() };
        assert_eq!(
            code & 0x7f_ffff,
            u64::try_from(ASN1_R_ILLEGAL_ZERO_CONTENT).unwrap()
        );
        // SAFETY: as above.
        unsafe { ASN1_item_free(value, &raw const PLAIN.0) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
