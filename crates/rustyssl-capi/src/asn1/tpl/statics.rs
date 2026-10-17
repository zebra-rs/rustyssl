//! Building blocks for the items rustyssl describes itself, as OpenSSL's `ASN1_SEQUENCE`,
//! `ASN1_CHOICE`, and `ASN1_ADB` macros make them: template tables, aux tables, and
//! ANY DEFINED BY tables, each in a static, and the items over them.

use core::ffi::{CStr, c_int, c_long, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_ADB, ASN1_ADB_TABLE, ASN1_AUX, ASN1_ITEM, ASN1_ITYPE_CHOICE, ASN1_ITYPE_SEQUENCE,
    ASN1_TEMPLATE, ASN1_TFLG_ADB_OID, ASN1_VALUE, V_ASN1_SEQUENCE,
};

use super::{Item, Template, item, size_of_long};

/// A table of templates in a static.
pub(crate) struct Templates<const N: usize>(pub(crate) [ASN1_TEMPLATE; N]);
// SAFETY: immutable tables of pointers to static data.
unsafe impl<const N: usize> Sync for Templates<N> {}

/// An aux table in a static.
pub(crate) struct Aux(pub(crate) ASN1_AUX);
// SAFETY: immutable, with no pointers but the callback.
unsafe impl Sync for Aux {}

/// An item's callback, as an aux table holds it.
pub(crate) type Callback =
    unsafe extern "C" fn(c_int, *mut *mut ASN1_VALUE, *const ASN1_ITEM, *mut c_void) -> c_int;

/// An aux table with callback `cb`, as `ASN1_SEQUENCE_cb` makes.
pub(crate) const fn aux(cb: Callback) -> Aux {
    Aux(ASN1_AUX {
        app_data: ptr::null_mut(),
        flags: 0,
        ref_offset: 0,
        ref_lock: 0,
        asn1_cb: Some(cb),
        enc_offset: 0,
        asn1_const_cb: None,
    })
}

/// An aux table with `flags`, the reference count at `ref_offset` and its lock at `ref_lock`
/// (`ASN1_AFLG_REFCOUNT`), callback `cb`, and the kept encoding at `enc_offset`
/// (`ASN1_AFLG_ENCODING`), as `ASN1_SEQUENCE_ref` and `ASN1_SEQUENCE_enc` make them.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "offsets within a structure"
)]
pub(crate) const fn aux_ex(
    flags: c_int,
    ref_offset: usize,
    ref_lock: usize,
    cb: Option<Callback>,
    enc_offset: usize,
) -> Aux {
    Aux(ASN1_AUX {
        app_data: ptr::null_mut(),
        flags,
        ref_offset: ref_offset as c_int,
        ref_lock: ref_lock as c_int,
        asn1_cb: cb,
        enc_offset: enc_offset as c_int,
        asn1_const_cb: None,
    })
}

/// A count of templates, as an item holds it.
#[expect(clippy::cast_possible_wrap, reason = "a handful of templates")]
const fn count(n: usize) -> c_long {
    n as c_long
}

/// An aux table's address for an item's `funcs`, or NULL.
const fn funcs(aux: Option<&'static Aux>) -> *const c_void {
    match aux {
        Some(a) => (&raw const a.0).cast(),
        None => ptr::null(),
    }
}

/// A SEQUENCE item over `T` with `templates` and `aux` (`ASN1_SEQUENCE`).
pub(crate) const fn sequence<T, const N: usize>(
    templates: &'static Templates<N>,
    aux: Option<&'static Aux>,
    sname: &'static CStr,
) -> Item {
    item(
        ASN1_ITYPE_SEQUENCE,
        V_ASN1_SEQUENCE,
        (&raw const templates.0).cast(),
        count(N),
        funcs(aux),
        size_of_long::<T>(),
        sname,
    )
}

/// A CHOICE item over `T`, whose `int` selector is at `selector` (`ASN1_CHOICE`): its `utype`
/// holds the selector's offset.
pub(crate) const fn choice<T, const N: usize>(
    templates: &'static Templates<N>,
    selector: usize,
    aux: Option<&'static Aux>,
    sname: &'static CStr,
) -> Item {
    #[expect(
        clippy::cast_possible_wrap,
        clippy::cast_possible_truncation,
        reason = "an offset in a small structure"
    )]
    let utype = selector as c_int;
    item(
        ASN1_ITYPE_CHOICE,
        utype,
        (&raw const templates.0).cast(),
        count(N),
        funcs(aux),
        size_of_long::<T>(),
        sname,
    )
}

/// An ANY DEFINED BY table's entries in a static.
pub(crate) struct AdbEntries<const N: usize>(pub(crate) [ASN1_ADB_TABLE; N]);
// SAFETY: immutable tables of pointers to static data.
unsafe impl<const N: usize> Sync for AdbEntries<N> {}

/// An entry: the template for the selector `value` (`ADB_ENTRY`).
pub(crate) const fn adb_entry(value: c_int, tt: ASN1_TEMPLATE) -> ASN1_ADB_TABLE {
    ASN1_ADB_TABLE {
        value: value as c_long,
        tt,
    }
}

/// An ANY DEFINED BY table in a static (`ASN1_ADB`), which an ADB template's item function
/// returns in place of an item.
pub(crate) struct Adb(pub(crate) ASN1_ADB);
// SAFETY: immutable, with pointers only to static tables and templates.
unsafe impl Sync for Adb {}

/// A table selected by the object at `offset` in the structure (`ASN1_ADB_END(..., 0,
/// field, 0, &default, NULL)`), with `default` for every other object.
pub(crate) const fn adb_oid<const N: usize>(
    offset: usize,
    entries: &'static AdbEntries<N>,
    default: &'static Template,
) -> Adb {
    Adb(ASN1_ADB {
        flags: 0,
        offset: offset as c_ulong,
        adb_cb: None,
        tbl: (&raw const entries.0).cast(),
        tblcount: count(N),
        default_tt: &raw const default.0,
        null_tt: ptr::null(),
    })
}

/// The template that holds an ANY DEFINED BY table (`ASN1_ADB_OBJECT`): `table` returns the
/// [`Adb`]'s address.
pub(crate) const fn adb_object(
    name: &'static CStr,
    table: unsafe extern "C" fn() -> *const ASN1_ITEM,
) -> ASN1_TEMPLATE {
    ASN1_TEMPLATE {
        flags: ASN1_TFLG_ADB_OID as c_ulong,
        tag: -1,
        offset: 0,
        field_name: name.as_ptr(),
        item: Some(table),
    }
}
