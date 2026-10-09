//! Allocating values from their items (`ASN1_item_new(3)`, `ASN1_item_ex_new`), as OpenSSL's
//! `tasn_new.c` does: a SEQUENCE or CHOICE is a zeroed structure of the item's size whose
//! fields are made in template order (optional ones, ANY DEFINED BY ones, and SET OF / SEQUENCE
//! OF stacks left empty or NULL), and a primitive is made by its item functions or by type.

use core::ffi::{c_char, c_int};
use core::ptr;

use rustyssl_abi::{
    ASN1_AUX, ASN1_EXTERN_FUNCS, ASN1_ITEM, ASN1_ITYPE_CHOICE, ASN1_ITYPE_EXTERN,
    ASN1_ITYPE_MSTRING, ASN1_ITYPE_NDEF_SEQUENCE, ASN1_ITYPE_PRIMITIVE, ASN1_ITYPE_SEQUENCE,
    ASN1_OP_NEW_POST, ASN1_OP_NEW_PRE, ASN1_PRIMITIVE_FUNCS, ASN1_R_AUX_ERROR, ASN1_STRING,
    ASN1_STRING_FLAG_EMBED, ASN1_STRING_FLAG_MSTRING, ASN1_TEMPLATE, ASN1_TFLG_ADB_MASK,
    ASN1_TFLG_EMBED, ASN1_TFLG_OPTIONAL, ASN1_TFLG_SK_MASK, ASN1_TYPE, ASN1_VALUE, ERR_LIB_ASN1,
    ERR_R_ASN1_LIB, ERR_R_CRYPTO_LIB, OSSL_LIB_CTX, V_ASN1_ANY, V_ASN1_BOOLEAN, V_ASN1_NULL,
    V_ASN1_OBJECT,
};

use super::{Pval, aux, field_ptr, free, itype, long_to_int, template_flags, template_item, utype};
use crate::asn1::string;
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;
use crate::stack;

/// How an item's construction failed, for the error OpenSSL raises.
enum Failure {
    /// Out of memory, raising nothing more.
    Silent,
    /// `ERR_R_ASN1_LIB`, after freeing what was made if `free`.
    Asn1 { free: bool },
    /// `ASN1_R_AUX_ERROR`, after freeing what was made if `free`.
    Aux { free: bool },
}

/// `asn1_item_embed_new`: makes a value of `it` in `*pval` (or, for an embedded one, in the
/// structure `*pval` points to). Returns 1, or 0 on failure.
///
/// # Safety
/// `pval` is valid for a write (for an embedded value, `*pval` points to room for one); `it`
/// is a live item whose tables and functions can be trusted.
pub(crate) unsafe fn embed_new(
    pval: Pval,
    it: *const ASN1_ITEM,
    embed: bool,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the caller's guarantee.
    match unsafe { construct(pval, it, embed, libctx, propq) } {
        Ok(()) => 1,
        Err(failure) => {
            let (reason, release) = match failure {
                Failure::Silent => return 0,
                Failure::Asn1 { free } => (ERR_R_ASN1_LIB, free),
                Failure::Aux { free } => (ASN1_R_AUX_ERROR, free),
            };
            if release {
                // SAFETY: what `construct` made so far.
                unsafe { free::embed_free(pval, it, embed) };
            }
            err::raise(ERR_LIB_ASN1, reason, "asn1_item_embed_new");
            0
        }
    }
}

/// The aux callback of a SEQUENCE or CHOICE item, if it has one.
///
/// # Safety
/// `it` is a live SEQUENCE, NDEF SEQUENCE, or CHOICE item.
pub(crate) unsafe fn aux_callback(it: *const ASN1_ITEM) -> rustyssl_abi::ASN1_aux_cb {
    // SAFETY: the caller's guarantee.
    let aux: *const ASN1_AUX = unsafe { aux(it) };
    if aux.is_null() {
        None
    } else {
        // SAFETY: a live aux.
        unsafe { (*aux).asn1_cb }
    }
}

/// The body of [`embed_new`], with its failures.
///
/// # Safety
/// As for [`embed_new`].
unsafe fn construct(
    pval: Pval,
    it: *const ASN1_ITEM,
    embed: bool,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> Result<(), Failure> {
    // SAFETY: the caller's guarantee.
    let kind = unsafe { itype(it) };
    // SAFETY: as above.
    let item = unsafe { &*it };
    match kind {
        ASN1_ITYPE_EXTERN => {
            let ef: *const ASN1_EXTERN_FUNCS = item.funcs.cast();
            if !ef.is_null() {
                // SAFETY: an extern item's funcs.
                let ef = unsafe { &*ef };
                if let Some(new_ex) = ef.asn1_ex_new_ex {
                    // SAFETY: the item's own function, with the caller's slot.
                    if unsafe { new_ex(pval, it, libctx, propq) } == 0 {
                        return Err(Failure::Asn1 { free: false });
                    }
                } else if let Some(new) = ef.asn1_ex_new {
                    // SAFETY: as above.
                    if unsafe { new(pval, it) } == 0 {
                        return Err(Failure::Asn1 { free: false });
                    }
                }
            }
        }
        ASN1_ITYPE_PRIMITIVE => {
            if item.templates.is_null() {
                // SAFETY: the caller's guarantee.
                if unsafe { primitive_new(pval, it, embed) } == 0 {
                    return Err(Failure::Asn1 { free: false });
                }
            // SAFETY: the item's template.
            } else if unsafe { template_new(pval, item.templates, libctx, propq) } == 0 {
                return Err(Failure::Asn1 { free: false });
            }
        }
        ASN1_ITYPE_MSTRING => {
            // SAFETY: the caller's guarantee.
            if unsafe { primitive_new(pval, it, embed) } == 0 {
                return Err(Failure::Asn1 { free: false });
            }
        }
        ASN1_ITYPE_CHOICE | ASN1_ITYPE_SEQUENCE | ASN1_ITYPE_NDEF_SEQUENCE => {
            // SAFETY: the caller's guarantee.
            let callback = unsafe { aux_callback(it) };
            if let Some(cb) = callback {
                // SAFETY: the application's callback, as OpenSSL calls it.
                let i = unsafe { cb(ASN1_OP_NEW_PRE, pval, it, ptr::null_mut()) };
                if i == 0 {
                    return Err(Failure::Aux { free: false });
                }
                if i == 2 {
                    return Ok(());
                }
            }
            let size = usize::try_from(item.size).unwrap_or(0);
            if embed {
                // SAFETY: the caller's slot.
                let room = unsafe { pval.read() };
                // SAFETY: an embedded value's room, of the item's size.
                unsafe { ptr::write_bytes(room.cast::<u8>(), 0, size) };
            } else {
                let block = mem::alloc_zeroed(size);
                if block.is_null() {
                    return Err(Failure::Silent);
                }
                // SAFETY: the caller's slot.
                unsafe { pval.write(block.cast()) };
            }
            if kind == ASN1_ITYPE_CHOICE {
                // SAFETY: a new CHOICE structure.
                unsafe { super::set_choice_selector(pval, -1, it) };
            } else {
                // SAFETY: a new SEQUENCE structure.
                if unsafe { super::do_lock(pval, 0, it) } < 0 {
                    if !embed {
                        // SAFETY: the caller's slot.
                        let block = unsafe { pval.read() };
                        // SAFETY: the structure just allocated.
                        unsafe { mem::release(block.cast()) };
                        // SAFETY: the caller's slot.
                        unsafe { pval.write(ptr::null_mut()) };
                    }
                    return Err(Failure::Asn1 { free: false });
                }
                // SAFETY: as above.
                unsafe { super::enc_init(pval, it) };
                let count = usize::try_from(item.tcount).unwrap_or(0);
                for i in 0..count {
                    let tt = item.templates.wrapping_add(i);
                    // SAFETY: the item has `tcount` templates, for fields of the structure.
                    let field = unsafe { field_ptr(pval, tt) };
                    // SAFETY: as above.
                    if unsafe { template_new(field, tt, libctx, propq) } == 0 {
                        return Err(Failure::Asn1 { free: true });
                    }
                }
            }
            if let Some(cb) = callback {
                // SAFETY: as above.
                if unsafe { cb(ASN1_OP_NEW_POST, pval, it, ptr::null_mut()) } == 0 {
                    return Err(Failure::Aux { free: true });
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// `asn1_template_new`: makes a template's field.
///
/// # Safety
/// `pval` is the field's slot (or the field, if embedded); `tt` is a live template.
unsafe fn template_new(
    pval: Pval,
    tt: *const ASN1_TEMPLATE,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let flags = unsafe { template_flags(tt) };
    // SAFETY: as above.
    let it = unsafe { template_item(tt) };
    let embed = flags & ASN1_TFLG_EMBED != 0;
    let mut tval: *mut ASN1_VALUE = pval.cast();
    let pval = if embed { &raw mut tval } else { pval };
    if flags & ASN1_TFLG_OPTIONAL != 0 {
        // SAFETY: the caller's guarantee.
        unsafe { template_clear(pval, tt) };
        return 1;
    }
    if flags & ASN1_TFLG_ADB_MASK != 0 {
        // SAFETY: the field's slot.
        unsafe { pval.write(ptr::null_mut()) };
        return 1;
    }
    if flags & ASN1_TFLG_SK_MASK != 0 {
        // SAFETY: no preconditions.
        let sk = unsafe { stack::OPENSSL_sk_new_null() };
        if sk.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_CRYPTO_LIB, "asn1_template_new");
            return 0;
        }
        // SAFETY: the field's slot.
        unsafe { pval.write(sk.cast()) };
        return 1;
    }
    // SAFETY: the caller's guarantee.
    unsafe { embed_new(pval, it, embed, libctx, propq) }
}

/// `asn1_template_clear`: sets an optional field to its absent value.
///
/// # Safety
/// As for [`template_new`].
unsafe fn template_clear(pval: Pval, tt: *const ASN1_TEMPLATE) {
    // SAFETY: the caller's guarantee.
    let flags = unsafe { template_flags(tt) };
    if flags & (ASN1_TFLG_ADB_MASK | ASN1_TFLG_SK_MASK) != 0 {
        // SAFETY: the field's slot.
        unsafe { pval.write(ptr::null_mut()) };
    } else {
        // SAFETY: as above.
        let it = unsafe { template_item(tt) };
        // SAFETY: as above.
        unsafe { item_clear(pval, it) };
    }
}

/// `asn1_item_clear`.
///
/// # Safety
/// `pval` is a slot for a value of the live item `it`.
unsafe fn item_clear(pval: Pval, it: *const ASN1_ITEM) {
    // SAFETY: the caller's guarantee.
    let item = unsafe { &*it };
    // SAFETY: as above.
    match unsafe { itype(it) } {
        ASN1_ITYPE_EXTERN => {
            // SAFETY: an extern item's funcs.
            let ef = unsafe { super::funcs::<ASN1_EXTERN_FUNCS>(it) };
            match ef.and_then(|ef| ef.asn1_ex_clear) {
                // SAFETY: the item's own function.
                Some(clear) => unsafe { clear(pval, it) },
                // SAFETY: the caller's slot.
                None => unsafe { pval.write(ptr::null_mut()) },
            }
        }
        ASN1_ITYPE_PRIMITIVE if !item.templates.is_null() => {
            // SAFETY: the item's template.
            unsafe { template_clear(pval, item.templates) };
        }
        // SAFETY: the caller's guarantee.
        ASN1_ITYPE_PRIMITIVE | ASN1_ITYPE_MSTRING => unsafe { primitive_clear(pval, it) },
        // SAFETY: the caller's slot.
        _ => unsafe { pval.write(ptr::null_mut()) },
    }
}

/// `asn1_primitive_new`.
///
/// # Safety
/// As for [`embed_new`], for a primitive or MSTRING item.
unsafe fn primitive_new(pval: Pval, it: *const ASN1_ITEM, embed: bool) -> c_int {
    if it.is_null() {
        return 0;
    }
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
                return 1;
            }
        } else if let Some(new) = pf.prim_new {
            // SAFETY: as above.
            return unsafe { new(pval, it) };
        }
    }
    // SAFETY: the caller's guarantee.
    let mstring = unsafe { itype(it) } == ASN1_ITYPE_MSTRING;
    // SAFETY: as above.
    let kind = if mstring { -1 } else { unsafe { utype(it) } };
    match kind {
        V_ASN1_OBJECT => {
            // SAFETY: no preconditions.
            let undef = unsafe { crate::objects::OBJ_nid2obj(0) };
            // SAFETY: the caller's slot.
            unsafe { pval.write(undef.cast()) };
            return 1;
        }
        V_ASN1_BOOLEAN => {
            // SAFETY: a BOOLEAN's slot is its `int`.
            unsafe { pval.cast::<c_int>().write(long_to_int(item.size)) };
            return 1;
        }
        V_ASN1_NULL => {
            // SAFETY: the caller's slot; NULL's value is the non-NULL pointer 1.
            unsafe { pval.write(ptr::without_provenance_mut(1)) };
            return 1;
        }
        V_ASN1_ANY => {
            let typ: *mut ASN1_TYPE = mem::alloc(size_of::<ASN1_TYPE>()).cast();
            if typ.is_null() {
                return 0;
            }
            // SAFETY: a new ASN1_TYPE, its fields written as OpenSSL writes them.
            let typ_ref = unsafe { &mut *typ };
            typ_ref.value.ptr = ptr::null_mut();
            typ_ref.type_ = -1;
            // SAFETY: the caller's slot.
            unsafe { pval.write(typ.cast()) };
        }
        _ => {
            let str: *mut ASN1_STRING = if embed {
                // SAFETY: an embedded string's room.
                let str: *mut ASN1_STRING = unsafe { pval.read() }.cast();
                // SAFETY: as above.
                unsafe { ptr::write_bytes(str, 0, 1) };
                // SAFETY: as above.
                unsafe { (*str).type_ = kind };
                // SAFETY: as above.
                unsafe { (*str).flags = ASN1_STRING_FLAG_EMBED.into() };
                str
            } else {
                let str = string::type_new(kind);
                // SAFETY: the caller's slot.
                unsafe { pval.write(str.cast()) };
                str
            };
            if mstring && !str.is_null() {
                // SAFETY: a live string.
                unsafe { (*str).flags |= core::ffi::c_long::from(ASN1_STRING_FLAG_MSTRING) };
            }
        }
    }
    // SAFETY: the caller's slot.
    c_int::from(!unsafe { pval.read() }.is_null())
}

/// `asn1_primitive_clear`.
///
/// # Safety
/// `pval` is a slot for a value of `it`, a live primitive or MSTRING item.
unsafe fn primitive_clear(pval: Pval, it: *const ASN1_ITEM) {
    // SAFETY: the caller's guarantee.
    let item = unsafe { &*it };
    if !item.funcs.is_null() {
        let pf: *const ASN1_PRIMITIVE_FUNCS = item.funcs.cast();
        // SAFETY: a primitive item's funcs.
        match unsafe { (*pf).prim_clear } {
            // SAFETY: the item's own function.
            Some(clear) => unsafe { clear(pval, it) },
            // SAFETY: the caller's slot.
            None => unsafe { pval.write(ptr::null_mut()) },
        }
        return;
    }
    // SAFETY: the caller's guarantee.
    let boolean =
        unsafe { itype(it) } != ASN1_ITYPE_MSTRING && unsafe { utype(it) } == V_ASN1_BOOLEAN;
    if boolean {
        // SAFETY: a BOOLEAN's slot is its `int`.
        unsafe { pval.cast::<c_int>().write(long_to_int(item.size)) };
    } else {
        // SAFETY: the caller's slot.
        unsafe { pval.write(ptr::null_mut()) };
    }
}

ffi_export! {
    /// A new value of `it` (`ASN1_item_ex_new` into a NULL slot), or NULL on failure.
    ///
    /// # Safety
    /// `it` is a live item whose tables and functions can be trusted.
    pub unsafe extern "C" fn ASN1_item_new(it: *const ASN1_ITEM) -> *mut ASN1_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        let mut ret: *mut ASN1_VALUE = ptr::null_mut();
        // SAFETY: the caller's guarantee, with a local slot.
        if unsafe { ASN1_item_ex_new(&raw mut ret, it) } > 0 { ret } else { ptr::null_mut() }
    }
}

ffi_export! {
    /// `ASN1_item_new`, passing `libctx` and `propq` to extern items that take them.
    ///
    /// # Safety
    /// As for `ASN1_item_new`; `propq` is NULL or a string.
    pub unsafe extern "C" fn ASN1_item_new_ex(it: *const ASN1_ITEM, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut ASN1_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        let mut ret: *mut ASN1_VALUE = ptr::null_mut();
        // SAFETY: the caller's guarantee, with a local slot.
        if unsafe { embed_new(&raw mut ret, it, false, libctx, propq) } > 0 { ret } else { ptr::null_mut() }
    }
}

ffi_export! {
    /// Makes a value of `it` in `*pval`. Returns 1, or 0 on failure.
    ///
    /// # Safety
    /// `pval` is valid for a write; `it` is as for `ASN1_item_new`.
    pub unsafe extern "C" fn ASN1_item_ex_new(pval: *mut *mut ASN1_VALUE, it: *const ASN1_ITEM) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { embed_new(pval, it, false, ptr::null_mut(), ptr::null()) }
    }
}
