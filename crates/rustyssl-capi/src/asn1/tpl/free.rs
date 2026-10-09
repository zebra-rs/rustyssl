//! Freeing values by their items (`ASN1_item_free(3)`, `ASN1_item_ex_free`), as OpenSSL's
//! `tasn_fre.c` does: a SEQUENCE drops a reference first (freeing nothing while others remain),
//! then frees its fields in reverse order (so an ANY DEFINED BY field is freed while its
//! selector still says what it holds), its cached encoding, and itself.

use core::ffi::c_int;
use core::ptr;

use rustyssl_abi::{
    ASN1_EXTERN_FUNCS, ASN1_ITEM, ASN1_ITYPE_CHOICE, ASN1_ITYPE_EXTERN, ASN1_ITYPE_MSTRING,
    ASN1_ITYPE_NDEF_SEQUENCE, ASN1_ITYPE_PRIMITIVE, ASN1_ITYPE_SEQUENCE, ASN1_OP_FREE_POST,
    ASN1_OP_FREE_PRE, ASN1_PRIMITIVE_FUNCS, ASN1_TEMPLATE, ASN1_TFLG_EMBED, ASN1_TFLG_SK_MASK,
    ASN1_TYPE, ASN1_VALUE, ERR_LIB_ASN1, V_ASN1_ANY, V_ASN1_BOOLEAN, V_ASN1_NULL, V_ASN1_OBJECT,
};

use super::new::aux_callback;
use super::{
    Pval, choice_selector, field_ptr, itype, long_to_int, template_flags, template_item, utype,
};
use crate::asn1::{any, string};
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects;
use crate::stack;

/// `ossl_asn1_item_embed_free`: frees the value of `it` in `*pval` (for an embedded one, only
/// what the structure holds) and clears the slot.
///
/// # Safety
/// `pval` is NULL or a slot holding NULL or a live value of `it` (for an embedded value,
/// `*pval` points to it); `it` is a live item whose tables and functions can be trusted.
pub(crate) unsafe fn embed_free(pval: Pval, it: *const ASN1_ITEM, embed: bool) {
    if pval.is_null() {
        return;
    }
    // SAFETY: the caller's guarantee.
    let kind = unsafe { itype(it) };
    // SAFETY: as above.
    if kind != ASN1_ITYPE_PRIMITIVE && unsafe { pval.read() }.is_null() {
        return;
    }
    // SAFETY: as above.
    let item = unsafe { &*it };
    match kind {
        ASN1_ITYPE_PRIMITIVE if !item.templates.is_null() => {
            // SAFETY: the item's template.
            unsafe { template_free(pval, item.templates) };
        }
        ASN1_ITYPE_PRIMITIVE | ASN1_ITYPE_MSTRING => {
            // SAFETY: the caller's guarantee.
            unsafe { primitive_free(pval, it, embed) };
        }
        ASN1_ITYPE_CHOICE => {
            // SAFETY: a CHOICE item.
            let callback = unsafe { aux_callback(it) };
            if let Some(cb) = callback {
                // SAFETY: the application's callback, as OpenSSL calls it.
                if unsafe { cb(ASN1_OP_FREE_PRE, pval, it, ptr::null_mut()) } == 2 {
                    return;
                }
            }
            // SAFETY: a live CHOICE structure.
            let i = unsafe { choice_selector(pval, it) };
            if let Ok(index) = usize::try_from(i)
                && c_long_lt(i, item.tcount)
            {
                let tt = item.templates.wrapping_add(index);
                // SAFETY: a template of the item, for a field of the structure.
                let field = unsafe { field_ptr(pval, tt) };
                // SAFETY: as above.
                unsafe { template_free(field, tt) };
            }
            if let Some(cb) = callback {
                // SAFETY: as above.
                unsafe { cb(ASN1_OP_FREE_POST, pval, it, ptr::null_mut()) };
            }
            if !embed {
                // SAFETY: the structure, from this allocator.
                unsafe { release(pval) };
            }
        }
        ASN1_ITYPE_EXTERN => {
            // SAFETY: an extern item's funcs.
            let ef = unsafe { super::funcs::<ASN1_EXTERN_FUNCS>(it) };
            if let Some(free) = ef.and_then(|ef| ef.asn1_ex_free) {
                // SAFETY: the item's own function.
                unsafe { free(pval, it) };
            }
        }
        ASN1_ITYPE_NDEF_SEQUENCE | ASN1_ITYPE_SEQUENCE => {
            // SAFETY: a live SEQUENCE structure.
            if unsafe { super::do_lock(pval, -1, it) } != 0 {
                // Still referenced, or failed: OpenSSL asserts this isn't embedded.
                // SAFETY: the caller's slot.
                unsafe { pval.write(ptr::null_mut()) };
                return;
            }
            // SAFETY: a SEQUENCE item.
            let callback = unsafe { aux_callback(it) };
            if let Some(cb) = callback {
                // SAFETY: the application's callback, as OpenSSL calls it.
                if unsafe { cb(ASN1_OP_FREE_PRE, pval, it, ptr::null_mut()) } == 2 {
                    return;
                }
            }
            // SAFETY: as above.
            unsafe { super::enc_free(pval, it) };
            let count = usize::try_from(item.tcount).unwrap_or(0);
            for i in (0..count).rev() {
                let tt = item.templates.wrapping_add(i);
                // SAFETY: the caller's slot.
                let structure = unsafe { pval.read() };
                // SAFETY: the structure and a template of the item.
                let seqtt = unsafe { super::do_adb(structure, tt, false) };
                if seqtt.is_null() {
                    continue;
                }
                // SAFETY: as above.
                let field = unsafe { field_ptr(pval, seqtt) };
                // SAFETY: as above.
                unsafe { template_free(field, seqtt) };
            }
            if let Some(cb) = callback {
                // SAFETY: as above.
                unsafe { cb(ASN1_OP_FREE_POST, pval, it, ptr::null_mut()) };
            }
            if !embed {
                // SAFETY: the structure, from this allocator.
                unsafe { release(pval) };
            }
        }
        _ => {}
    }
}

/// `i < tcount`, as C compares an `int` with a `long`.
fn c_long_lt(i: c_int, count: core::ffi::c_long) -> bool {
    core::ffi::c_long::from(i) < count
}

/// Frees the block in `*pval` and clears the slot.
///
/// # Safety
/// `pval` holds NULL or a block from this allocator.
unsafe fn release(pval: Pval) {
    // SAFETY: the caller's guarantee.
    let block = unsafe { pval.read() };
    // SAFETY: as above.
    unsafe { mem::release(block.cast()) };
    // SAFETY: as above.
    unsafe { pval.write(ptr::null_mut()) };
}

/// `ossl_asn1_template_free`: frees a template's field (each element of a SET OF or SEQUENCE
/// OF, then the stack).
///
/// # Safety
/// `pval` is the field's slot (or the field, if embedded); `tt` is a live template.
pub(crate) unsafe fn template_free(pval: Pval, tt: *const ASN1_TEMPLATE) {
    // SAFETY: the caller's guarantee.
    let flags = unsafe { template_flags(tt) };
    // SAFETY: as above.
    let it = unsafe { template_item(tt) };
    let embed = flags & ASN1_TFLG_EMBED != 0;
    let mut tval: *mut ASN1_VALUE = pval.cast();
    let pval = if embed { &raw mut tval } else { pval };
    if flags & ASN1_TFLG_SK_MASK != 0 {
        // SAFETY: the field's slot holds a stack, or NULL.
        let sk: *mut rustyssl_abi::OPENSSL_STACK = unsafe { pval.read() }.cast();
        // SAFETY: as above; the count is re-read each time, as OpenSSL does.
        let mut i = 0;
        // SAFETY: as above.
        while i < unsafe { stack::OPENSSL_sk_num(sk) } {
            // SAFETY: as above.
            let mut vtmp: *mut ASN1_VALUE = unsafe { stack::OPENSSL_sk_value(sk, i) }.cast();
            // SAFETY: an element of the stack, a value of the item.
            unsafe { embed_free(&raw mut vtmp, it, embed) };
            i = i.wrapping_add(1);
        }
        // SAFETY: as above.
        unsafe { stack::OPENSSL_sk_free(sk) };
        // SAFETY: the field's slot.
        unsafe { pval.write(ptr::null_mut()) };
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { embed_free(pval, it, embed) };
    }
}

/// `ossl_asn1_primitive_free` with an item.
///
/// # Safety
/// `pval` is a slot holding NULL or a live value of `it`, a primitive or MSTRING item.
pub(crate) unsafe fn primitive_free(pval: Pval, it: *const ASN1_ITEM, embed: bool) {
    // SAFETY: the caller's guarantee.
    let item = unsafe { &*it };
    let pf: *const ASN1_PRIMITIVE_FUNCS = item.funcs.cast();
    if !pf.is_null() {
        // SAFETY: a primitive item's funcs.
        let pf = unsafe { &*pf };
        if embed {
            if let Some(clear) = pf.prim_clear {
                // SAFETY: the item's own function.
                unsafe { clear(pval, it) };
                return;
            }
        } else if let Some(free) = pf.prim_free {
            // SAFETY: as above.
            unsafe { free(pval, it) };
            return;
        }
    }
    // SAFETY: the caller's guarantee.
    let mstring = unsafe { itype(it) } == ASN1_ITYPE_MSTRING;
    // SAFETY: as above.
    let kind = if mstring { -1 } else { unsafe { utype(it) } };
    // SAFETY: the caller's slot.
    let value = unsafe { pval.read() };
    if kind != V_ASN1_BOOLEAN && value.is_null() {
        return;
    }
    match kind {
        // SAFETY: an OBJECT's value is an object.
        V_ASN1_OBJECT => unsafe { objects::free_object(value.cast()) },
        V_ASN1_BOOLEAN => {
            // SAFETY: a BOOLEAN's slot is its `int`.
            unsafe { pval.cast::<c_int>().write(long_to_int(item.size)) };
            return;
        }
        V_ASN1_NULL => {}
        V_ASN1_ANY => {
            let typ: *mut ASN1_TYPE = value.cast();
            // SAFETY: an ANY's value is an ASN1_TYPE, from this allocator.
            unsafe { any::free_value(typ) };
            // SAFETY: as above.
            unsafe { mem::release(typ.cast()) };
        }
        // SAFETY: any other value is a string.
        _ => unsafe { string::embed_free(value.cast(), embed) },
    }
    // SAFETY: the caller's slot.
    unsafe { pval.write(ptr::null_mut()) };
}

ffi_export! {
    /// Frees `val`, a value of `it`. NULL does nothing.
    ///
    /// # Safety
    /// `val` is NULL or a live value of `it`, a live item whose tables and functions can be
    /// trusted.
    pub unsafe extern "C" fn ASN1_item_free(val: *mut ASN1_VALUE, it: *const ASN1_ITEM)
    where failure = (), library = ERR_LIB_ASN1
    {
        let mut val = val;
        // SAFETY: the caller's guarantee, with a local slot.
        unsafe { embed_free(&raw mut val, it, false) };
    }
}

ffi_export! {
    /// Frees the value of `it` in `*pval` and sets it to NULL.
    ///
    /// # Safety
    /// `pval` is NULL or a slot holding NULL or a live value of `it`; `it` as for
    /// `ASN1_item_free`.
    pub unsafe extern "C" fn ASN1_item_ex_free(pval: *mut *mut ASN1_VALUE, it: *const ASN1_ITEM)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { embed_free(pval, it, false) };
    }
}
