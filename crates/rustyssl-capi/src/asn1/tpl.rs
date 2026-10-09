//! The template engine: `ASN1_ITEM`s and `ASN1_TEMPLATE`s, the tables that describe ASN.1 types
//! and the C structures holding their values (`ASN1_item_new(3)`, `ASN1_item_i2d(3)`,
//! `ASN1_ITEM`). Applications define their own with the `asn1t.h` macros, so the engine walks
//! tables from both rustyssl and the application, the way OpenSSL's `tasn_*.c` do.
//!
//! The tables are code, trusted as the C compiler trusts them: offsets into the structures,
//! sizes, and the item functions they name. What the engine never trusts is the data it encodes
//! and decodes. Every step is a port of OpenSSL's, in its order, because applications see the
//! order: their aux callbacks run at the same points (`ASN1_OP_*_PRE`/`_POST`), as often, and
//! the two-pass encoder (a pass to size, then one to write) calls them in both passes.
//!
//! The submodules are [`new`] and [`free`] (allocation, `tasn_new.c` and `tasn_fre.c`),
//! [`encode`] (`tasn_enc.c`), [`items`] (the universal types' items and functions,
//! `tasn_typ.c`), and [`ints`] (the `INT32`..`ZUINT64` and `LONG` items, `x_int64.c` and
//! `x_long.c`).

pub(crate) mod decode;
pub(crate) mod encode;
pub(crate) mod free;
pub(crate) mod ints;
pub(crate) mod io;
pub(crate) mod items;
pub(crate) mod new;
pub(crate) mod util;

use core::ffi::{CStr, c_char, c_int, c_long, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use rustyssl_abi::{
    ASN1_ADB, ASN1_AFLG_ENCODING, ASN1_AFLG_REFCOUNT, ASN1_AUX, ASN1_ENCODING, ASN1_ITEM,
    ASN1_ITYPE_NDEF_SEQUENCE, ASN1_ITYPE_SEQUENCE, ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE,
    ASN1_TEMPLATE, ASN1_TFLG_ADB_MASK, ASN1_TFLG_ADB_OID, ASN1_VALUE, CRYPTO_RWLOCK, ERR_LIB_ASN1,
    ERR_R_CRYPTO_LIB,
};

use crate::err;
use crate::mem;

/// Defines `_it` functions, each returning its item from a static.
macro_rules! item_fns {
    ($(
        $(#[$attr:meta])*
        pub unsafe extern "C" fn $name:ident = $item:expr;
    )*) => {$(
        $crate::ffi::ffi_export! {
            $(#[$attr])*
            ///
            /// # Safety
            /// No preconditions.
            pub unsafe extern "C" fn $name() -> *const ASN1_ITEM
            where failure = ::core::ptr::null(), library = ERR_LIB_ASN1
            {
                static ITEM: $crate::asn1::tpl::Item = $item;
                &raw const ITEM.0
            }
        }
    )*};
}
pub(crate) use item_fns;

/// An item in a static, for an `_it` function to return.
#[repr(transparent)]
pub(crate) struct Item(pub(crate) ASN1_ITEM);

// SAFETY: an item is immutable, and its pointers lead only to other immutable statics: templates,
// funcs tables, and names.
unsafe impl Sync for Item {}

/// A template in a static, for an item to point to.
#[repr(transparent)]
pub(crate) struct Template(pub(crate) ASN1_TEMPLATE);

// SAFETY: as for `Item`.
unsafe impl Sync for Template {}

/// A primitive item's functions in a static.
#[repr(transparent)]
pub(crate) struct PrimitiveFuncs(pub(crate) rustyssl_abi::ASN1_PRIMITIVE_FUNCS);

// SAFETY: as for `Item`; its `app_data` is NULL.
unsafe impl Sync for PrimitiveFuncs {}

/// A size in an item's `size`.
#[expect(
    clippy::cast_possible_wrap,
    reason = "the sizes of C structures, far below `LONG_MAX`"
)]
pub(crate) const fn size_of_long<T>() -> c_long {
    size_of::<T>() as c_long
}

/// An item, as `ASN1_ITEM_start(name) itype, utype, templates, tcount, funcs, size, #name`.
pub(crate) const fn item(
    itype: c_int,
    utype: c_int,
    templates: *const ASN1_TEMPLATE,
    tcount: c_long,
    funcs: *const c_void,
    size: c_long,
    sname: &'static CStr,
) -> Item {
    Item(ASN1_ITEM {
        itype: c_char::from_le_bytes([itype.to_le_bytes()[0]]),
        utype: utype as c_long,
        templates,
        tcount,
        funcs,
        size,
        sname: sname.as_ptr(),
    })
}

/// A template, as `ASN1_EX_TEMPLATE_TYPE(flags, tag, name, type)` at offset 0.
pub(crate) const fn template(
    flags: c_int,
    tag: c_long,
    field_name: &'static CStr,
    item: unsafe extern "C" fn() -> *const ASN1_ITEM,
) -> Template {
    Template(ASN1_TEMPLATE {
        flags: flags.cast_unsigned() as c_ulong,
        tag,
        offset: 0,
        field_name: field_name.as_ptr(),
        item: Some(item),
    })
}

/// A template at `offset` in its structure, as `ASN1_EX_TYPE(flags, tag, stname, field, type)`.
pub(crate) const fn template_at(
    flags: c_int,
    tag: c_long,
    offset: usize,
    field_name: &'static CStr,
    item: unsafe extern "C" fn() -> *const ASN1_ITEM,
) -> ASN1_TEMPLATE {
    ASN1_TEMPLATE {
        flags: flags.cast_unsigned() as c_ulong,
        tag,
        offset: offset as c_ulong,
        field_name: field_name.as_ptr(),
        item: Some(item),
    }
}

/// A C string's bytes, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a string.
pub(crate) unsafe fn cstr_bytes<'a>(s: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) }.to_bytes())
}

/// A value's slot, as the engine passes it: `ASN1_VALUE **`. For an embedded field or a BOOLEAN
/// it is really the address of the field itself.
pub(crate) type Pval = *mut *mut ASN1_VALUE;

/// An item's type (`ASN1_ITYPE_*`).
///
/// # Safety
/// `it` is a live item.
pub(crate) unsafe fn itype(it: *const ASN1_ITEM) -> c_int {
    // SAFETY: the caller's guarantee.
    c_int::from(unsafe { (*it).itype })
}

/// An item's underlying type (`utype`), as OpenSSL truncates it to an `int`.
///
/// # Safety
/// `it` is a live item.
pub(crate) unsafe fn utype(it: *const ASN1_ITEM) -> c_int {
    // SAFETY: the caller's guarantee.
    long_to_int(unsafe { (*it).utype })
}

/// C's conversion of a `long` to an `int`: the low 32 bits.
pub(crate) fn long_to_int(value: c_long) -> c_int {
    let [a, b, c, d, ..] = value.to_le_bytes();
    c_int::from_le_bytes([a, b, c, d])
}

/// The item a template names (`ASN1_ITEM_ptr(tt->item)`), or NULL if it names none.
///
/// # Safety
/// `tt` is a live template whose item function, if any, can be called.
pub(crate) unsafe fn template_item(tt: *const ASN1_TEMPLATE) -> *const ASN1_ITEM {
    // SAFETY: the caller's guarantee.
    match unsafe { (*tt).item } {
        // SAFETY: an item function takes no arguments.
        Some(item) => unsafe { item() },
        None => ptr::null(),
    }
}

/// A template's flags, as OpenSSL reads them into an `int`.
///
/// # Safety
/// `tt` is a live template.
pub(crate) unsafe fn template_flags(tt: *const ASN1_TEMPLATE) -> c_int {
    // SAFETY: the caller's guarantee.
    let flags = unsafe { (*tt).flags };
    let [a, b, c, d, ..] = flags.to_le_bytes();
    c_int::from_le_bytes([a, b, c, d])
}

/// An item's funcs as `T`: its extern or primitive functions, if it has them.
///
/// # Safety
/// `it` is a live item whose funcs, if not NULL, are a `T`.
pub(crate) unsafe fn funcs<'a, T>(it: *const ASN1_ITEM) -> Option<&'a T> {
    // SAFETY: the caller's guarantee.
    let funcs = unsafe { (*it).funcs };
    // SAFETY: as above.
    unsafe { funcs.cast::<T>().as_ref() }
}

/// The aux data of a SEQUENCE or CHOICE item (its `funcs`), or NULL.
///
/// # Safety
/// `it` is a live SEQUENCE, NDEF SEQUENCE, or CHOICE item.
pub(crate) unsafe fn aux(it: *const ASN1_ITEM) -> *const ASN1_AUX {
    // SAFETY: the caller's guarantee.
    unsafe { (*it).funcs }.cast()
}

/// The pointer `offset` octets into the structure `*pval` points to (`offset2ptr`).
///
/// # Safety
/// `pval` is valid for a read.
pub(crate) unsafe fn offset_ptr<T>(pval: Pval, offset: usize) -> *mut T {
    // SAFETY: the caller's guarantee.
    unsafe { *pval }.cast::<u8>().wrapping_add(offset).cast()
}

/// A field's slot in the structure `*pval` points to (`ossl_asn1_get_field_ptr`).
///
/// # Safety
/// `pval` is valid for a read; `tt` is a live template.
pub(crate) unsafe fn field_ptr(pval: Pval, tt: *const ASN1_TEMPLATE) -> Pval {
    // SAFETY: the caller's guarantee.
    let offset = unsafe { (*tt).offset };
    // SAFETY: as above.
    unsafe { offset_ptr(pval, usize::try_from(offset).unwrap_or(0)) }
}

/// A CHOICE's selector, the `int` at offset `utype` in its structure.
///
/// # Safety
/// `pval` holds a live CHOICE structure of `it`.
pub(crate) unsafe fn choice_selector(pval: Pval, it: *const ASN1_ITEM) -> c_int {
    // SAFETY: the caller's guarantee.
    let offset = usize::try_from(unsafe { (*it).utype }).unwrap_or(0);
    // SAFETY: as above.
    let selector = unsafe { offset_ptr::<c_int>(pval, offset) };
    // SAFETY: the selector is within the structure.
    unsafe { selector.read_unaligned() }
}

/// Sets a CHOICE's selector, returning the old one.
///
/// # Safety
/// As for [`choice_selector`].
pub(crate) unsafe fn set_choice_selector(pval: Pval, value: c_int, it: *const ASN1_ITEM) -> c_int {
    // SAFETY: the caller's guarantee.
    let offset = usize::try_from(unsafe { (*it).utype }).unwrap_or(0);
    // SAFETY: as above.
    let selector = unsafe { offset_ptr::<c_int>(pval, offset) };
    // SAFETY: the selector is within the structure.
    let old = unsafe { selector.read_unaligned() };
    // SAFETY: as above.
    unsafe { selector.write_unaligned(value) };
    old
}

/// `ossl_asn1_do_lock`: for a SEQUENCE with `ASN1_AFLG_REFCOUNT`, `op` 0 starts the count at 1
/// (and makes its lock), 1 adds a reference, -1 drops one (freeing the lock at 0). Returns the
/// new count, 0 for an item without one, or -1 on failure.
///
/// # Safety
/// `pval` holds a live structure of `it`.
pub(crate) unsafe fn do_lock(pval: Pval, op: c_int, it: *const ASN1_ITEM) -> c_int {
    // SAFETY: the caller's guarantee.
    let kind = unsafe { itype(it) };
    if kind != ASN1_ITYPE_SEQUENCE && kind != ASN1_ITYPE_NDEF_SEQUENCE {
        return 0;
    }
    // SAFETY: a SEQUENCE's funcs are its aux data.
    let aux = unsafe { aux(it) };
    // SAFETY: as above.
    if aux.is_null() || unsafe { (*aux).flags } & ASN1_AFLG_REFCOUNT == 0 {
        return 0;
    }
    // SAFETY: a live aux.
    let aux = unsafe { &*aux };
    let (ref_offset, lock_offset) = (aux.ref_offset, aux.ref_lock);
    // SAFETY: the count and lock are fields of the structure.
    let count = unsafe { offset_ptr::<i32>(pval, usize::try_from(ref_offset).unwrap_or(0)) };
    // SAFETY: as above.
    let lock = unsafe {
        offset_ptr::<*mut CRYPTO_RWLOCK>(pval, usize::try_from(lock_offset).unwrap_or(0))
    };
    // SAFETY: an `int` field, aligned as C aligns it, used only atomically here.
    let counter = unsafe { AtomicI32::from_ptr(count) };
    match op {
        0 => {
            counter.store(1, Ordering::Relaxed);
            // SAFETY: no preconditions.
            let made = unsafe { crate::threads::CRYPTO_THREAD_lock_new() };
            if made.is_null() {
                err::raise(ERR_LIB_ASN1, ERR_R_CRYPTO_LIB, "ossl_asn1_do_lock");
                return -1;
            }
            // SAFETY: the lock field.
            unsafe { lock.write(made) };
            1
        }
        1 => counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1),
        -1 => {
            let left = counter.fetch_sub(1, Ordering::AcqRel).wrapping_sub(1);
            if left == 0 {
                // SAFETY: the lock field.
                let made = unsafe { lock.read() };
                // SAFETY: the lock made by op 0.
                unsafe { crate::threads::CRYPTO_THREAD_lock_free(made) };
                // SAFETY: as above.
                unsafe { lock.write(ptr::null_mut()) };
            }
            left
        }
        _ => -1,
    }
}

/// The ENCODING cache of a SEQUENCE with `ASN1_AFLG_ENCODING`, or NULL.
///
/// # Safety
/// `pval` is NULL or holds NULL or a live structure of the SEQUENCE `it`.
pub(crate) unsafe fn enc_ptr(pval: Pval, it: *const ASN1_ITEM) -> *mut ASN1_ENCODING {
    // SAFETY: the caller's guarantee.
    if pval.is_null() || unsafe { *pval }.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: as above.
    let aux = unsafe { aux(it) };
    // SAFETY: as above.
    if aux.is_null() || unsafe { (*aux).flags } & ASN1_AFLG_ENCODING == 0 {
        return ptr::null_mut();
    }
    // SAFETY: as above.
    let offset = unsafe { (*aux).enc_offset };
    // SAFETY: the cache is a field of the structure.
    unsafe { offset_ptr(pval, usize::try_from(offset).unwrap_or(0)) }
}

/// `ossl_asn1_enc_init`: an empty, modified cache.
///
/// # Safety
/// As for [`enc_ptr`].
pub(crate) unsafe fn enc_init(pval: Pval, it: *const ASN1_ITEM) {
    // SAFETY: the caller's guarantee.
    let enc = unsafe { enc_ptr(pval, it) };
    if !enc.is_null() {
        // SAFETY: a live cache.
        unsafe {
            enc.write(ASN1_ENCODING {
                enc: ptr::null_mut(),
                len: 0,
                modified: 1,
            })
        };
    }
}

/// `ossl_asn1_enc_free`: frees the cached encoding.
///
/// # Safety
/// As for [`enc_ptr`].
pub(crate) unsafe fn enc_free(pval: Pval, it: *const ASN1_ITEM) {
    // SAFETY: the caller's guarantee.
    let enc = unsafe { enc_ptr(pval, it) };
    if !enc.is_null() {
        // SAFETY: a live cache.
        let old = unsafe { (*enc).enc };
        // SAFETY: its encoding came from this allocator.
        unsafe { mem::release(old.cast()) };
        // SAFETY: as above.
        unsafe {
            enc.write(ASN1_ENCODING {
                enc: ptr::null_mut(),
                len: 0,
                modified: 1,
            })
        };
    }
}

/// `ossl_asn1_enc_save`: keeps a copy of the encoding a SEQUENCE was decoded from. Returns 1,
/// or 0 for an empty encoding or no memory.
///
/// # Safety
/// As for [`enc_ptr`].
pub(crate) unsafe fn enc_save(pval: Pval, encoding: &[u8], it: *const ASN1_ITEM) -> c_int {
    // SAFETY: the caller's guarantee.
    let enc = unsafe { enc_ptr(pval, it) };
    if enc.is_null() {
        return 1;
    }
    // SAFETY: a live cache.
    let cache = unsafe { &mut *enc };
    // SAFETY: its encoding came from this allocator.
    unsafe { mem::release(cache.enc.cast()) };
    cache.enc = ptr::null_mut();
    if encoding.is_empty() {
        return 0;
    }
    let copy: *mut u8 = mem::alloc(encoding.len()).cast();
    if copy.is_null() {
        return 0;
    }
    // SAFETY: a new block of the encoding's size.
    unsafe { ptr::copy_nonoverlapping(encoding.as_ptr(), copy, encoding.len()) };
    cache.enc = copy;
    cache.len = c_long::try_from(encoding.len()).unwrap_or(c_long::MAX);
    cache.modified = 0;
    1
}

/// `ossl_asn1_do_adb`: the template a field uses, through its ANY DEFINED BY table if it has one
/// (chosen by the selector field's OID or INTEGER, after the table's callback). NULL if the
/// table has no entry for it (raising `ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE` if `nullerr`).
///
/// # Safety
/// `val` is a live structure holding the template's fields; `tt` is a live template.
pub(crate) unsafe fn do_adb(
    val: *const ASN1_VALUE,
    tt: *const ASN1_TEMPLATE,
    nullerr: bool,
) -> *const ASN1_TEMPLATE {
    // SAFETY: the caller's guarantee.
    let flags = unsafe { template_flags(tt) };
    if flags & ASN1_TFLG_ADB_MASK == 0 {
        return tt;
    }
    // SAFETY: an ADB template's item function returns its table.
    let adb: *const ASN1_ADB = unsafe { template_item(tt) }.cast();
    let fail = || {
        if nullerr {
            err::raise(
                ERR_LIB_ASN1,
                ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE,
                "ossl_asn1_do_adb",
            );
        }
        ptr::null()
    };
    if adb.is_null() {
        return fail();
    }
    // SAFETY: a live table.
    let table = unsafe { &*adb };
    let mut holder = val.cast_mut();
    let selector_field: *mut *mut c_void =
        // SAFETY: the selector is a field of the structure.
        unsafe { offset_ptr((&raw mut holder).cast(), usize::try_from(table.offset).unwrap_or(0)) };
    // SAFETY: as above.
    let selector_value = unsafe { selector_field.read() };
    if selector_value.is_null() {
        if table.null_tt.is_null() {
            return fail();
        }
        return table.null_tt;
    }
    let mut selector: c_long = if flags & ASN1_TFLG_ADB_OID != 0 {
        // SAFETY: an OID selector is an object.
        c_long::from(unsafe { crate::objects::OBJ_obj2nid(selector_value.cast()) })
    } else {
        // SAFETY: an INTEGER selector is an integer.
        unsafe { super::integer::ASN1_INTEGER_get(selector_value.cast()) }
    };
    if let Some(callback) = table.adb_cb {
        // SAFETY: the application's callback, with a local.
        if unsafe { callback(&raw mut selector) } == 0 {
            err::raise(
                ERR_LIB_ASN1,
                ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE,
                "ossl_asn1_do_adb",
            );
            return ptr::null();
        }
    }
    let count = usize::try_from(table.tblcount).unwrap_or(0);
    for i in 0..count {
        let entry = table.tbl.wrapping_add(i);
        // SAFETY: the table holds `tblcount` entries.
        if unsafe { (*entry).value } == selector {
            // SAFETY: as above.
            return unsafe { &raw const (*entry).tt };
        }
    }
    if table.default_tt.is_null() {
        return fail();
    }
    table.default_tt
}
