//! Objects: OIDs with their NIDs and names (`OBJ_nid2obj(3)`, `OBJ_create(3)`,
//! `OBJ_obj2txt(3)`, `OBJ_bsearch_`), the `ASN1_OBJECT` itself (`ASN1_OBJECT_new(3)`,
//! `a2d_ASN1_OBJECT`, `i2a_ASN1_OBJECT`), and, in [`name`] and [`sigid`], the name registry and
//! the signature-algorithm table.
//!
//! `ASN1_OBJECT` is opaque to applications; it has OpenSSL's layout and flags anyway. The
//! built-in objects (from `rustyssl_asn1::objects`) live at fixed addresses for the life of the
//! process and are never freed, so `OBJ_nid2obj` and `OBJ_txt2obj` hand them out shared, as
//! OpenSSL does; `ASN1_OBJECT_free` leaves them (and objects added at run time) alone because
//! they aren't marked dynamic. Lookups search the built-in objects first, exactly as OpenSSL's
//! binary searches do (which decide between objects sharing a name or an OID), then the
//! objects added by `OBJ_create` and `OBJ_add_object`, which are kept for the life of the
//! process as well.

pub(crate) mod name;
pub(crate) mod sigid;

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::{OnceLock, PoisonError, RwLock};

use rustyssl_abi::{
    ASN1_OBJECT, ASN1_R_BAD_OBJECT_HEADER, ASN1_R_BUFFER_TOO_SMALL, ASN1_R_EXPECTING_AN_OBJECT,
    ASN1_R_FIRST_NUM_TOO_LARGE, ASN1_R_INVALID_DIGIT, ASN1_R_INVALID_OBJECT_ENCODING,
    ASN1_R_INVALID_SEPARATOR, ASN1_R_LENGTH_TOO_LONG, ASN1_R_MISSING_SECOND_NUMBER,
    ASN1_R_SECOND_NUMBER_TOO_LARGE, ASN1_R_TOO_SMALL, BIO, ERR_LIB_ASN1, ERR_LIB_OBJ,
    ERR_R_ASN1_LIB, ERR_R_PASSED_INVALID_ARGUMENT, NID_undef, OBJ_BSEARCH_FIRST_VALUE_ON_MATCH,
    OBJ_BSEARCH_VALUE_ON_NOMATCH, OBJ_R_OID_EXISTS, OBJ_R_UNKNOWN_NID, OBJ_R_UNKNOWN_OBJECT_NAME,
    OPENSSL_INIT_LOAD_CONFIG, V_ASN1_OBJECT,
};
use rustyssl_asn1::der;
use rustyssl_asn1::objects as table;
use rustyssl_asn1::oid::{self, TextError};

use crate::err;
use crate::ffi::ffi_export;
use crate::mem;

/// The object is on the heap: `ASN1_OBJECT_free` frees it.
pub(crate) const FLAG_DYNAMIC: c_int = 0x01;
/// Its names are on the heap.
pub(crate) const FLAG_DYNAMIC_STRINGS: c_int = 0x04;
/// Its content octets are on the heap.
pub(crate) const FLAG_DYNAMIC_DATA: c_int = 0x08;
const FLAGS_ALL_DYNAMIC: c_int = FLAG_DYNAMIC | FLAG_DYNAMIC_STRINGS | FLAG_DYNAMIC_DATA;

/// OpenSSL's `struct asn1_object_st`.
#[repr(C)]
pub(crate) struct Object {
    pub(crate) sn: *const c_char,
    pub(crate) ln: *const c_char,
    pub(crate) nid: c_int,
    pub(crate) length: c_int,
    pub(crate) data: *const u8,
    pub(crate) flags: c_int,
}

/// A pointer to an object that is never freed (built in or added), shareable between threads.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Kept(*mut Object);

// SAFETY: kept objects are never freed, and rustyssl never writes to them after they're
// published; what applications do through the pointers is theirs, as in OpenSSL.
unsafe impl Send for Kept {}
// SAFETY: as for `Send`.
unsafe impl Sync for Kept {}

/// The built-in objects, indexed by NID; unassigned NIDs are zeroed entries, as in OpenSSL.
fn builtins() -> &'static [Kept] {
    static BUILTINS: OnceLock<Vec<Kept>> = OnceLock::new();
    BUILTINS.get_or_init(|| {
        let name = |text: &str| -> *const c_char {
            CString::new(text).map_or(ptr::null(), |s| s.into_raw().cast_const())
        };
        table::objects()
            .iter()
            .map(|entry| {
                let object = match entry {
                    Some(def) => Object {
                        sn: name(def.short_name),
                        ln: name(def.long_name),
                        nid: def.nid,
                        length: c_int::try_from(def.der.len()).unwrap_or(0),
                        data: if def.der.is_empty() {
                            ptr::null()
                        } else {
                            def.der.as_ptr()
                        },
                        flags: 0,
                    },
                    None => Object {
                        sn: ptr::null(),
                        ln: ptr::null(),
                        nid: NID_undef,
                        length: 0,
                        data: ptr::null(),
                        flags: 0,
                    },
                };
                Kept(Box::into_raw(Box::new(object)))
            })
            .collect()
    })
}

/// The objects added at run time, by each of their keys. A newer object with the same key
/// replaces an older one for that key only, as in OpenSSL's table.
#[derive(Default)]
struct Added {
    by_data: HashMap<Vec<u8>, Kept>,
    by_short_name: HashMap<Vec<u8>, Kept>,
    by_long_name: HashMap<Vec<u8>, Kept>,
    by_nid: HashMap<c_int, Kept>,
}

static ADDED: RwLock<Option<Added>> = RwLock::new(None);

/// OpenSSL loads the configuration file (which can add objects) before it first consults the
/// added objects; its result doesn't matter here, as it doesn't there. (Miri can't run the
/// system calls that finds the file with, and its tests have no configuration.)
fn before_added() {
    if cfg!(miri) {
        return;
    }
    let flag = u64::try_from(OPENSSL_INIT_LOAD_CONFIG).unwrap_or(0);
    // SAFETY: no settings.
    let _ = unsafe { crate::init::OPENSSL_init_crypto(flag, ptr::null()) };
}

/// Looks up an added object.
fn added(find: impl FnOnce(&Added) -> Option<Kept>) -> Option<Kept> {
    before_added();
    let added = ADDED.read().unwrap_or_else(PoisonError::into_inner);
    added.as_ref().and_then(find)
}

/// Reserves `count` NIDs, returning the first: OpenSSL hands them out from the first past the
/// built-in table.
fn next_nid(count: c_int) -> c_int {
    static NEXT: OnceLock<AtomicI32> = OnceLock::new();
    NEXT.get_or_init(|| {
        AtomicI32::new(c_int::try_from(table::objects().len()).unwrap_or(c_int::MAX))
    })
    .fetch_add(count, Ordering::Relaxed)
}

/// The bytes of a C string, or `None` for NULL.
///
/// # Safety
/// `text` is NULL or a NUL-terminated string that outlives the result.
unsafe fn c_text<'a>(text: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    (!text.is_null()).then(|| unsafe { CStr::from_ptr(text) }.to_bytes())
}

/// An object's content octets: none when its data is NULL or its length isn't positive.
///
/// # Safety
/// `object` is a live object whose data, if any, holds `length` bytes.
unsafe fn content<'a>(object: *const Object) -> &'a [u8] {
    // SAFETY: the caller's guarantee.
    let object = unsafe { &*object };
    let (data, length) = (object.data, object.length);
    match usize::try_from(length) {
        // SAFETY: the caller's guarantee.
        Ok(length) if length > 0 && !data.is_null() => unsafe {
            core::slice::from_raw_parts(data, length)
        },
        _ => &[],
    }
}

/// `OBJ_nid2obj`: the built-in object, else the added one, else NULL with
/// `OBJ_R_UNKNOWN_NID`.
fn nid2obj(nid: c_int) -> *mut Object {
    let builtins = builtins();
    if let Some(Kept(object)) = usize::try_from(nid).ok().and_then(|i| builtins.get(i)) {
        // SAFETY: built-in objects are always live.
        if nid == NID_undef || unsafe { (**object).nid } != NID_undef {
            return *object;
        }
    }
    if let Some(Kept(object)) = added(|a| a.by_nid.get(&nid).copied()) {
        return object;
    }
    err::raise(ERR_LIB_OBJ, OBJ_R_UNKNOWN_NID, "OBJ_nid2obj");
    ptr::null_mut()
}

/// `OBJ_obj2nid`.
///
/// # Safety
/// `object` is NULL or a live object.
unsafe fn obj2nid(object: *const Object) -> c_int {
    if object.is_null() {
        return NID_undef;
    }
    // SAFETY: the caller's guarantee.
    let view = unsafe { &*object };
    let (nid, length) = (view.nid, view.length);
    if nid != NID_undef {
        return nid;
    }
    if length == 0 {
        return NID_undef;
    }
    // SAFETY: the caller's guarantee.
    let data = unsafe { content(object) };
    if let Some(nid) = table::by_der(data) {
        return nid;
    }
    // SAFETY: added objects are always live.
    added(|a| a.by_data.get(data).copied()).map_or(NID_undef, |Kept(o)| unsafe { (*o).nid })
}

/// `OBJ_sn2nid` and `OBJ_ln2nid` for a name.
fn name2nid(name: &[u8], long: bool) -> c_int {
    let builtin = if long {
        table::by_long_name(name)
    } else {
        table::by_short_name(name)
    };
    if let Some(nid) = builtin {
        return nid;
    }
    let found = added(|a| {
        let map = if long {
            &a.by_long_name
        } else {
            &a.by_short_name
        };
        map.get(name).copied()
    });
    // SAFETY: added objects are always live.
    found.map_or(NID_undef, |Kept(o)| unsafe { (*o).nid })
}

/// Raises the error `a2d_ASN1_OBJECT` raises for `error`.
fn raise_text_error(error: TextError) {
    let reason = match error {
        TextError::FirstNumTooLarge => ASN1_R_FIRST_NUM_TOO_LARGE,
        TextError::MissingSecondNumber => ASN1_R_MISSING_SECOND_NUMBER,
        TextError::InvalidSeparator => ASN1_R_INVALID_SEPARATOR,
        TextError::InvalidDigit => ASN1_R_INVALID_DIGIT,
        TextError::SecondNumberTooLarge => ASN1_R_SECOND_NUMBER_TOO_LARGE,
        TextError::BufferTooSmall => ASN1_R_BUFFER_TOO_SMALL,
    };
    err::raise(ERR_LIB_ASN1, reason, "a2d_ASN1_OBJECT");
}

/// A copy of `bytes` as a NUL-terminated string in C memory, or NULL.
fn c_string(bytes: &[u8]) -> *mut c_char {
    let Some(size) = bytes.len().checked_add(1) else {
        return ptr::null_mut();
    };
    let copy: *mut u8 = mem::alloc(size).cast();
    if !copy.is_null() {
        // SAFETY: `copy` has room for the bytes and the NUL.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), copy, bytes.len()) };
        // SAFETY: the last byte of the block.
        unsafe { copy.wrapping_add(bytes.len()).write(0) };
    }
    copy.cast()
}

/// A new, zeroed, dynamic object (`ASN1_OBJECT_new`), or NULL.
fn new_object() -> *mut Object {
    let object: *mut Object = mem::alloc_zeroed(size_of::<Object>()).cast();
    if !object.is_null() {
        // SAFETY: just allocated, zeroed, and big enough.
        unsafe { (*object).flags = FLAG_DYNAMIC };
    }
    object
}

/// `ASN1_OBJECT_free`.
///
/// # Safety
/// `object` is NULL or a live object, not used afterwards if it is dynamic.
pub(crate) unsafe fn free_object(object: *mut Object) {
    if object.is_null() {
        return;
    }
    // SAFETY: the caller's guarantee; the reference ends before the object is freed.
    let target = unsafe { &mut *object };
    let flags = target.flags;
    if flags & FLAG_DYNAMIC_STRINGS != 0 {
        // SAFETY: dynamic strings came from this allocator.
        unsafe { mem::release(target.sn.cast_mut().cast()) };
        // SAFETY: as above.
        unsafe { mem::release(target.ln.cast_mut().cast()) };
        target.sn = ptr::null();
        target.ln = ptr::null();
    }
    if flags & FLAG_DYNAMIC_DATA != 0 {
        // SAFETY: dynamic data came from this allocator.
        unsafe { mem::release(target.data.cast_mut().cast()) };
        target.data = ptr::null();
        target.length = 0;
    }
    if flags & FLAG_DYNAMIC != 0 {
        // SAFETY: a dynamic object came from this allocator.
        unsafe { mem::release(object.cast()) };
    }
}

/// `OBJ_dup`: the object itself if it isn't dynamic (it is never freed), else a dynamic copy
/// with its own data and names.
///
/// # Safety
/// `object` is NULL or a live object.
unsafe fn dup(object: *const Object) -> *mut Object {
    if object.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller's guarantee.
    let source = unsafe { &*object };
    if source.flags & FLAG_DYNAMIC == 0 {
        return object.cast_mut();
    }
    let copy = new_object();
    if copy.is_null() {
        err::raise(ERR_LIB_OBJ, ERR_R_ASN1_LIB, "OBJ_dup");
        return ptr::null_mut();
    }
    // SAFETY: a fresh object, not yet shared.
    let target = unsafe { &mut *copy };
    target.flags = source.flags | FLAGS_ALL_DYNAMIC;
    let mut ok = true;
    if source.length > 0 {
        // SAFETY: the caller's guarantee about the source.
        let data = unsafe { content(object) };
        if data.is_empty() {
            ok = false;
        } else {
            let copied: *mut u8 = mem::alloc(data.len()).cast();
            if copied.is_null() {
                ok = false;
            } else {
                // SAFETY: `copied` has room for the data.
                unsafe { ptr::copy_nonoverlapping(data.as_ptr(), copied, data.len()) };
                target.data = copied;
            }
        }
    }
    target.length = source.length;
    target.nid = source.nid;
    for (from, to) in [(source.ln, &mut target.ln), (source.sn, &mut target.sn)] {
        // SAFETY: the caller's guarantee: the source's names are strings.
        if ok && let Some(text) = unsafe { c_text(from) } {
            let copied = c_string(text);
            ok = !copied.is_null();
            *to = copied;
        }
    }
    if !ok {
        // SAFETY: the copy, with what it holds so far.
        unsafe { free_object(copy) };
        return ptr::null_mut();
    }
    copy
}

/// `OBJ_add_object` (and `OBJ_create`'s last step): keeps a copy of `object` for the life of
/// the process under its NID, content octets, and names. Returns its NID, or `NID_undef`.
///
/// # Safety
/// `object` is NULL or a live object.
unsafe fn add_object(object: *const Object) -> c_int {
    // SAFETY: the caller's guarantee.
    let kept = unsafe { dup(object) };
    if kept.is_null() {
        return NID_undef;
    }
    // SAFETY: a copy (or a kept object), live.
    let view = unsafe { &*kept };
    let nid = view.nid;
    // SAFETY: as above.
    let data = unsafe { content(kept) }.to_vec();
    // SAFETY: its names are strings.
    let sn = unsafe { c_text(view.sn) };
    // SAFETY: as above.
    let ln = unsafe { c_text(view.ln) };
    if kept.cast_const() != object {
        // SAFETY: the copy isn't shared yet; from now on it is kept and never freed.
        unsafe { (*kept).flags &= !FLAGS_ALL_DYNAMIC };
    }
    before_added();
    let mut added = ADDED.write().unwrap_or_else(PoisonError::into_inner);
    let added = added.get_or_insert_with(Added::default);
    if !data.is_empty() {
        added.by_data.insert(data, Kept(kept));
    }
    if let Some(sn) = sn {
        added.by_short_name.insert(sn.to_vec(), Kept(kept));
    }
    if let Some(ln) = ln {
        added.by_long_name.insert(ln.to_vec(), Kept(kept));
    }
    added.by_nid.insert(nid, Kept(kept));
    nid
}

/// `OBJ_txt2obj`.
///
/// # Safety
/// `text` is a NUL-terminated string.
unsafe fn txt2obj(text: &[u8], no_name: bool) -> *mut Object {
    if !no_name {
        let mut nid = name2nid(text, false);
        if nid == NID_undef {
            nid = name2nid(text, true);
        }
        if nid != NID_undef {
            return nid2obj(nid);
        }
        if !text.first().is_some_and(u8::is_ascii_digit) {
            err::raise(ERR_LIB_OBJ, OBJ_R_UNKNOWN_OBJECT_NAME, "OBJ_txt2obj");
            return ptr::null_mut();
        }
    }
    let encoded = oid::encode_text(text, None);
    if let Some(error) = encoded.error {
        raise_text_error(error);
        return ptr::null_mut();
    }
    let data = encoded.octets;
    let Ok(length) = c_int::try_from(data.len()) else {
        return ptr::null_mut();
    };
    if length == 0 {
        return ptr::null_mut();
    }
    // As `d2i_ASN1_OBJECT` does with the encoding.
    let _ = length;
    // SAFETY: no object to reuse.
    unsafe { c2i(ptr::null_mut(), &data) }
}

/// OpenSSL's `ossl_c2i_ASN1_OBJECT`: an object from OID content octets. A known OID gives the
/// shared object (replacing `*a`, freed); otherwise the content must be a valid encoding, and
/// goes into `*a` if that is a dynamic object (keeping its NID, dropping its names) or into a
/// new one. Raises `ASN1_R_INVALID_OBJECT_ENCODING` for bad content.
///
/// # Safety
/// `a` is NULL or points to NULL or a live object.
pub(crate) unsafe fn c2i(a: *mut *mut Object, content: &[u8]) -> *mut Object {
    let invalid = || {
        err::raise(
            ERR_LIB_ASN1,
            ASN1_R_INVALID_OBJECT_ENCODING,
            "ossl_c2i_ASN1_OBJECT",
        );
        ptr::null_mut()
    };
    let Ok(length) = c_int::try_from(content.len()) else {
        return invalid();
    };
    if content.last().is_none_or(|&last| last & 0x80 != 0) {
        return invalid();
    }
    let probe = Object {
        sn: ptr::null(),
        ln: ptr::null(),
        nid: NID_undef,
        length,
        data: content.as_ptr(),
        flags: 0,
    };
    // SAFETY: a live object on the stack.
    let nid = unsafe { obj2nid(&raw const probe) };
    if nid != NID_undef {
        let shared = nid2obj(nid);
        if !a.is_null() {
            // SAFETY: the caller's guarantee.
            let old = unsafe { *a };
            // SAFETY: the caller's object, replaced below.
            unsafe { free_object(old) };
            // SAFETY: as above.
            unsafe { *a = shared };
        }
        return shared;
    }
    if !oid::is_valid_content(content) {
        return invalid();
    }
    let existing = if a.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { *a }
    };
    // SAFETY: as above.
    let reuse = !existing.is_null() && unsafe { (*existing).flags } & FLAG_DYNAMIC != 0;
    let object = if reuse { existing } else { new_object() };
    if object.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a dynamic object, the caller's or a new one.
    let target = unsafe { &mut *object };
    // Content octets are reused if they're the object's own and big enough.
    let own = target.flags & FLAG_DYNAMIC_DATA != 0;
    let mut data = if own {
        target.data.cast_mut()
    } else {
        ptr::null_mut()
    };
    target.data = ptr::null();
    if data.is_null() || target.length < length {
        target.length = 0;
        // SAFETY: the object's own data, from this allocator (or NULL).
        unsafe { mem::release(data.cast()) };
        data = mem::alloc(content.len()).cast();
        if data.is_null() {
            if !reuse {
                // SAFETY: the new object.
                unsafe { free_object(object) };
            }
            return ptr::null_mut();
        }
        target.flags |= FLAG_DYNAMIC_DATA;
    }
    // SAFETY: `data` has room for the content.
    unsafe { ptr::copy_nonoverlapping(content.as_ptr(), data, content.len()) };
    if target.flags & FLAG_DYNAMIC_STRINGS != 0 {
        // SAFETY: dynamic strings came from this allocator.
        unsafe { mem::release(target.sn.cast_mut().cast()) };
        // SAFETY: as above.
        unsafe { mem::release(target.ln.cast_mut().cast()) };
        target.flags &= !FLAG_DYNAMIC_STRINGS;
    }
    target.data = data;
    target.length = length;
    target.sn = ptr::null();
    target.ln = ptr::null();
    if !a.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { *a = object };
    }
    object
}

ffi_export! {
    /// Decodes an OBJECT IDENTIFIER (of any class, primitive or not, as in OpenSSL) from at
    /// most `length` octets at `*pp`, moving `*pp` past it: the shared object for a known OID,
    /// else a new object, or the reused `*a`. NULL with an error otherwise.
    ///
    /// Unlike OpenSSL, NULL `pp` or `*pp` returns NULL rather than crashing
    /// (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `*pp` is valid for reads of `length` octets (or of the whole element); `a` is NULL or
    /// points to NULL or a live object.
    pub unsafe extern "C" fn d2i_ASN1_OBJECT(a: *mut *mut ASN1_OBJECT, pp: *mut *const u8, length: c_long) -> *mut ASN1_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let start = if pp.is_null() { ptr::null() } else { unsafe { *pp } };
        if start.is_null() {
            return ptr::null_mut();
        }
        if length <= 0 {
            err::raise(ERR_LIB_ASN1, ASN1_R_TOO_SMALL, "ASN1_get_object");
            err::raise(ERR_LIB_ASN1, ASN1_R_BAD_OBJECT_HEADER, "d2i_ASN1_OBJECT");
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let header = match unsafe { crate::asn1::read_header(start, length) } {
            Ok(h) if !h.overrun => h,
            _ => {
                err::raise(ERR_LIB_ASN1, ASN1_R_BAD_OBJECT_HEADER, "d2i_ASN1_OBJECT");
                return ptr::null_mut();
            }
        };
        if header.tag != V_ASN1_OBJECT {
            err::raise(ERR_LIB_ASN1, ASN1_R_EXPECTING_AN_OBJECT, "d2i_ASN1_OBJECT");
            return ptr::null_mut();
        }
        let content_start = start.wrapping_add(header.header_len);
        let content = match usize::try_from(header.length) {
            // Within what the header says remains of `length`.
            Ok(n) if n > 0 && c_int::try_from(n).is_ok() => {
                // SAFETY: the header's length is within the input the caller provides.
                unsafe { core::slice::from_raw_parts(content_start, n) }
            }
            _ => &[],
        };
        // SAFETY: the caller's guarantee about `a`.
        let object = unsafe { c2i(a.cast(), content) };
        if !object.is_null() {
            // SAFETY: past the element, within the input.
            unsafe { *pp = content_start.wrapping_add(content.len()) };
        }
        object.cast()
    }
}

ffi_export! {
    /// Encodes `a` as an OBJECT IDENTIFIER: its size with NULL `pp`; else written at `*pp`
    /// (moved past it), or into a new buffer (stored in `*pp`) if `*pp` is NULL. 0 for an
    /// object without content, -1 if it's too long.
    ///
    /// # Safety
    /// `a` is NULL or a live object; `pp` is NULL or valid, and `*pp` NULL or valid for writes
    /// of the encoding.
    pub unsafe extern "C" fn i2d_ASN1_OBJECT(a: *const ASN1_OBJECT, pp: *mut *mut u8) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        let object: *const Object = a.cast();
        // SAFETY: the caller's guarantee.
        if object.is_null() || unsafe { (*object).data }.is_null() {
            return 0;
        }
        // SAFETY: as above.
        let length = unsafe { (*object).length };
        let size = der::object_size(0, length, V_ASN1_OBJECT);
        if pp.is_null() || size == -1 {
            return size;
        }
        let mut encoding = Vec::new();
        der::put_header(&mut encoding, 0, length, V_ASN1_OBJECT, 0);
        // SAFETY: the object's content.
        encoding.extend_from_slice(unsafe { content(object) });
        // SAFETY: the caller's guarantee.
        let target = unsafe { *pp };
        let out = if target.is_null() {
            mem::alloc(encoding.len()).cast::<u8>()
        } else {
            target
        };
        if out.is_null() {
            return 0;
        }
        // SAFETY: room for the encoding, the caller's or just allocated.
        unsafe { ptr::copy_nonoverlapping(encoding.as_ptr(), out, encoding.len()) };
        // SAFETY: as above.
        unsafe { *pp = if target.is_null() { out } else { out.wrapping_add(encoding.len()) } };
        size
    }
}

/// What `OBJ_obj2txt` produces: its result and the text it writes (a prefix of the whole text
/// when it fails partway).
///
/// # Safety
/// `object` is NULL or a live object.
unsafe fn obj2txt(object: *const Object, no_name: bool) -> (c_int, Vec<u8>) {
    // SAFETY: the caller's guarantee.
    if object.is_null() || unsafe { (*object).data }.is_null() {
        return (0, Vec::new());
    }
    if !no_name {
        // SAFETY: the caller's guarantee.
        let nid = unsafe { obj2nid(object) };
        if nid != NID_undef {
            let name = nid2obj(nid);
            let mut text = if name.is_null() {
                ptr::null()
            } else {
                // SAFETY: a returned object is live.
                unsafe { (*name).ln }
            };
            if text.is_null() {
                let name = nid2obj(nid);
                text = if name.is_null() {
                    ptr::null()
                } else {
                    // SAFETY: as above.
                    unsafe { (*name).sn }
                };
            }
            // SAFETY: object names are strings.
            if let Some(text) = unsafe { c_text(text) } {
                return (
                    c_int::try_from(text.len()).unwrap_or(c_int::MAX),
                    text.to_vec(),
                );
            }
        }
    }
    // SAFETY: the caller's guarantee.
    let decoded = oid::decode_text(unsafe { content(object) });
    let result = if decoded.complete {
        c_int::try_from(decoded.text.len()).unwrap_or(c_int::MAX)
    } else {
        -1
    };
    (result, decoded.text)
}

/// Writes as much of `text` as fits into `buf` (`size` bytes) with a NUL, as OpenSSL's string
/// copies do; nothing for no room.
///
/// # Safety
/// `buf` is NULL or valid for `size` bytes of writes.
unsafe fn write_text(buf: *mut c_char, size: c_int, text: &[u8]) {
    let Ok(size) = usize::try_from(size) else {
        return;
    };
    if buf.is_null() || size == 0 {
        return;
    }
    let n = text.len().min(size.saturating_sub(1));
    // SAFETY: `n` + 1 bytes fit in the caller's buffer.
    unsafe { ptr::copy_nonoverlapping(text.as_ptr(), buf.cast(), n) };
    // SAFETY: as above.
    unsafe { buf.wrapping_add(n).write(0) };
}

ffi_export! {
    /// The object with NID `n`, shared and never freed; NULL with `OBJ_R_UNKNOWN_NID` if
    /// there's none.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OBJ_nid2obj(n: c_int) -> *mut ASN1_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_OBJ
    {
        nid2obj(n).cast()
    }
}

ffi_export! {
    /// The short name of NID `n`, or NULL with `OBJ_R_UNKNOWN_NID`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OBJ_nid2sn(n: c_int) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OBJ
    {
        let object = nid2obj(n);
        // SAFETY: a returned object is live.
        if object.is_null() { ptr::null() } else { unsafe { (*object).sn } }
    }
}

ffi_export! {
    /// The long name of NID `n`, or NULL with `OBJ_R_UNKNOWN_NID`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OBJ_nid2ln(n: c_int) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OBJ
    {
        let object = nid2obj(n);
        // SAFETY: a returned object is live.
        if object.is_null() { ptr::null() } else { unsafe { (*object).ln } }
    }
}

ffi_export! {
    /// The NID of `o`: its own, else that of the known object with its OID, else `NID_undef`.
    ///
    /// # Safety
    /// `o` is NULL or a live object.
    pub unsafe extern "C" fn OBJ_obj2nid(o: *const ASN1_OBJECT) -> c_int
    where failure = NID_undef, library = ERR_LIB_OBJ
    {
        // SAFETY: the caller's guarantee.
        unsafe { obj2nid(o.cast()) }
    }
}

ffi_export! {
    /// The NID of the object with short name `s` (exactly), or `NID_undef`.
    ///
    /// Unlike OpenSSL, NULL is `NID_undef` rather than a crash (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `s` is NULL or a NUL-terminated string.
    pub unsafe extern "C" fn OBJ_sn2nid(s: *const c_char) -> c_int
    where failure = NID_undef, library = ERR_LIB_OBJ
    {
        // SAFETY: the caller's guarantee.
        unsafe { c_text(s) }.map_or(NID_undef, |s| name2nid(s, false))
    }
}

ffi_export! {
    /// The NID of the object with long name `s` (exactly), or `NID_undef`.
    ///
    /// Unlike OpenSSL, NULL is `NID_undef` rather than a crash (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `s` is NULL or a NUL-terminated string.
    pub unsafe extern "C" fn OBJ_ln2nid(s: *const c_char) -> c_int
    where failure = NID_undef, library = ERR_LIB_OBJ
    {
        // SAFETY: the caller's guarantee.
        unsafe { c_text(s) }.map_or(NID_undef, |s| name2nid(s, true))
    }
}

ffi_export! {
    /// The object named `s` (a short name, a long name, or, with `no_name`, only) dotted
    /// numbers: a shared object if it is known, else a new one to free with
    /// `ASN1_OBJECT_free`. NULL if `s` is neither.
    ///
    /// Unlike OpenSSL, NULL `s` gives NULL rather than a crash (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `s` is NULL or a NUL-terminated string.
    pub unsafe extern "C" fn OBJ_txt2obj(s: *const c_char, no_name: c_int) -> *mut ASN1_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_OBJ
    {
        // SAFETY: the caller's guarantee.
        match unsafe { c_text(s) } {
            // SAFETY: as above.
            Some(text) => unsafe { txt2obj(text, no_name != 0) }.cast(),
            None => ptr::null_mut(),
        }
    }
}

ffi_export! {
    /// The NID of the object `s` names (as `OBJ_txt2obj` reads it), or `NID_undef`.
    ///
    /// # Safety
    /// `s` is NULL or a NUL-terminated string.
    pub unsafe extern "C" fn OBJ_txt2nid(s: *const c_char) -> c_int
    where failure = NID_undef, library = ERR_LIB_OBJ
    {
        // SAFETY: the caller's guarantee.
        let Some(text) = (unsafe { c_text(s) }) else {
            return NID_undef;
        };
        // SAFETY: as above.
        let object = unsafe { txt2obj(text, false) };
        // SAFETY: a returned object is live.
        let nid = unsafe { obj2nid(object) };
        // SAFETY: freed only if it was made for this call.
        unsafe { free_object(object) };
        nid
    }
}

ffi_export! {
    /// Writes `a`'s long name (or short name; with `no_name`, or for an unknown OID, its dotted
    /// numbers) into `buf`, as much as fits in `buf_len` bytes with a NUL. Returns the whole
    /// text's length, 0 for an object without content, or -1 for content that isn't an OID
    /// (having written the arcs before the fault).
    ///
    /// Unlike OpenSSL, a negative `buf_len` writes nothing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `buf` is NULL or valid for `buf_len` bytes of writes; `a` is NULL or a live object.
    pub unsafe extern "C" fn OBJ_obj2txt(buf: *mut c_char, buf_len: c_int, a: *const ASN1_OBJECT, no_name: c_int) -> c_int
    where failure = -1, library = ERR_LIB_OBJ
    {
        // SAFETY: the caller's guarantee.
        unsafe { write_text(buf, buf_len, &[]) };
        // SAFETY: the caller's guarantee.
        let (result, text) = unsafe { obj2txt(a.cast(), no_name != 0) };
        // SAFETY: the caller's guarantee.
        unsafe { write_text(buf, buf_len, &text) };
        result
    }
}

ffi_export! {
    /// `OBJ_obj2txt` with names.
    ///
    /// # Safety
    /// As for `OBJ_obj2txt`.
    pub unsafe extern "C" fn i2t_ASN1_OBJECT(buf: *mut c_char, buf_len: c_int, a: *const ASN1_OBJECT) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { OBJ_obj2txt(buf, buf_len, a, 0) }
    }
}

ffi_export! {
    /// Writes `a` as `i2t_ASN1_OBJECT` names it to `bp`: `NULL` for no object or one without
    /// content, `<INVALID>` and a hex dump for content that isn't an OID. Returns the text's
    /// length, or what writing the placeholder returned.
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `a` is NULL or a live object.
    pub unsafe extern "C" fn i2a_ASN1_OBJECT(bp: *mut BIO, a: *const ASN1_OBJECT) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        let object: *const Object = a.cast();
        // SAFETY: the caller's guarantee.
        if object.is_null() || unsafe { (*object).data }.is_null() {
            // SAFETY: the caller's guarantee about `bp`.
            return unsafe { crate::bio::BIO_write(bp, c"NULL".as_ptr().cast(), 4) };
        }
        // SAFETY: the caller's guarantee.
        let (result, text) = unsafe { obj2txt(object, false) };
        if result == c_int::MAX {
            err::raise(ERR_LIB_ASN1, ASN1_R_LENGTH_TOO_LONG, "i2a_ASN1_OBJECT");
            return -1;
        }
        if result <= 0 {
            // SAFETY: the caller's guarantee about `bp`.
            let mut written = unsafe { crate::bio::BIO_write(bp, c"<INVALID>".as_ptr().cast(), 9) };
            if written > 0 {
                // SAFETY: the object's content.
                let data = unsafe { content(object) };
                let length = c_int::try_from(data.len()).unwrap_or(0);
                // SAFETY: the caller's guarantee about `bp`; `data` holds `length` bytes.
                let dumped = unsafe { crate::bio::dump::BIO_dump(bp, data.as_ptr().cast(), length) };
                written = written.wrapping_add(dumped);
            }
            return written;
        }
        // SAFETY: the caller's guarantee about `bp`; `text` holds `result` bytes.
        let _ = unsafe { crate::bio::BIO_write(bp, text.as_ptr().cast(), result) };
        result
    }
}

ffi_export! {
    /// Encodes dotted `buf` (`num` bytes, or to its NUL for -1) as OID content octets into
    /// `out` (`olen` bytes), or with NULL `out` only measures them. Returns their length, or 0
    /// (with an error for text that isn't an OID).
    ///
    /// Unlike OpenSSL, NULL `buf` returns 0 rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `buf` is NULL or holds `num` bytes (a NUL-terminated string for -1); `out` is NULL or
    /// valid for `olen` bytes of writes.
    pub unsafe extern "C" fn a2d_ASN1_OBJECT(out: *mut u8, olen: c_int, buf: *const c_char, num: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if num == 0 || buf.is_null() {
            return 0;
        }
        let text: &[u8] = match usize::try_from(num) {
            // SAFETY: the caller's guarantee.
            Ok(num) => unsafe { core::slice::from_raw_parts(buf.cast(), num) },
            // SAFETY: as above.
            Err(_) if num == -1 => unsafe { CStr::from_ptr(buf) }.to_bytes(),
            // OpenSSL reads one character, then finds the text over.
            // SAFETY: as above.
            Err(_) => unsafe { core::slice::from_raw_parts(buf.cast(), 1) },
        };
        let capacity = (!out.is_null()).then(|| usize::try_from(olen).unwrap_or(0));
        let encoded = oid::encode_text(text, capacity);
        if !out.is_null() {
            // SAFETY: the octets fit in `olen` bytes, which the caller provides.
            unsafe { ptr::copy_nonoverlapping(encoded.octets.as_ptr(), out, encoded.octets.len()) };
        }
        match encoded.error {
            Some(error) => {
                raise_text_error(error);
                0
            }
            None => c_int::try_from(encoded.octets.len()).unwrap_or(0),
        }
    }
}

ffi_export! {
    /// Adds an object with dotted OID `oid`, short name `sn`, and long name `ln` (each may be
    /// NULL, not all), under a new NID, which it returns. 0 if a name or the OID is already
    /// known (`OBJ_R_OID_EXISTS`) or `oid` isn't dotted numbers.
    ///
    /// # Safety
    /// Each of `oid`, `sn`, and `ln` is NULL or a NUL-terminated string.
    pub unsafe extern "C" fn OBJ_create(oid: *const c_char, sn: *const c_char, ln: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_OBJ
    {
        if oid.is_null() && sn.is_null() && ln.is_null() {
            err::raise(ERR_LIB_OBJ, ERR_R_PASSED_INVALID_ARGUMENT, "OBJ_create");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let oid_text = unsafe { c_text(oid) };
        // SAFETY: as above.
        let short = unsafe { c_text(sn) };
        // SAFETY: as above.
        let long = unsafe { c_text(ln) };
        if short.is_some_and(|s| name2nid(s, false) != NID_undef)
            || long.is_some_and(|l| name2nid(l, true) != NID_undef)
        {
            err::raise(ERR_LIB_OBJ, OBJ_R_OID_EXISTS, "OBJ_create");
            return 0;
        }
        let made = match oid_text {
            // SAFETY: a string.
            Some(text) => unsafe { txt2obj(text, true) },
            None => {
                let object = new_object();
                if object.is_null() {
                    err::raise(ERR_LIB_OBJ, ERR_R_ASN1_LIB, "OBJ_create");
                }
                object
            }
        };
        if made.is_null() {
            return 0;
        }
        // SAFETY: a live object.
        if oid_text.is_some() && unsafe { obj2nid(made) } != NID_undef {
            err::raise(ERR_LIB_OBJ, OBJ_R_OID_EXISTS, "OBJ_create");
            // SAFETY: freed only if it was made here.
            unsafe { free_object(made) };
            return 0;
        }
        {
            // SAFETY: an object made here (a known one was refused above), not shared.
            let target = unsafe { &mut *made };
            target.nid = next_nid(1);
            target.sn = sn;
            target.ln = ln;
        }
        // SAFETY: a live object; the copy takes its own names.
        let nid = unsafe { add_object(made) };
        {
            // SAFETY: as above; the names are the caller's, so they're detached before freeing.
            let target = unsafe { &mut *made };
            target.sn = ptr::null();
            target.ln = ptr::null();
        }
        // SAFETY: made here.
        unsafe { free_object(made) };
        nid
    }
}

ffi_export! {
    /// Adds a copy of `obj` under its NID, OID, and names; returns its NID.
    ///
    /// Unlike OpenSSL, adding a built-in object keeps it as it is rather than crashing on a
    /// write to read-only memory (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `obj` is NULL or a live object.
    pub unsafe extern "C" fn OBJ_add_object(obj: *const ASN1_OBJECT) -> c_int
    where failure = NID_undef, library = ERR_LIB_OBJ
    {
        // SAFETY: the caller's guarantee.
        unsafe { add_object(obj.cast()) }
    }
}

ffi_export! {
    /// Reserves `num` NIDs, returning the first.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OBJ_new_nid(num: c_int) -> c_int
    where failure = NID_undef, library = ERR_LIB_OBJ
    {
        next_nid(num)
    }
}

ffi_export! {
    /// `o` itself if it isn't dynamic (built-in and added objects), else a copy.
    ///
    /// # Safety
    /// `o` is NULL or a live object.
    pub unsafe extern "C" fn OBJ_dup(o: *const ASN1_OBJECT) -> *mut ASN1_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_OBJ
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup(o.cast()) }.cast()
    }
}

ffi_export! {
    /// Compares two objects' OIDs: by length, then bytes; 0 if equal.
    ///
    /// Unlike OpenSSL, a NULL object sorts first rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `a` and `b` are NULL or live objects.
    pub unsafe extern "C" fn OBJ_cmp(a: *const ASN1_OBJECT, b: *const ASN1_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_OBJ
    {
        let (a, b): (*const Object, *const Object) = (a.cast(), b.cast());
        match (a.is_null(), b.is_null()) {
            (true, true) => return 0,
            (true, false) => return -1,
            (false, true) => return 1,
            (false, false) => {}
        }
        // SAFETY: the caller's guarantee.
        let a_length = unsafe { (*a).length };
        // SAFETY: as above.
        let difference = a_length.wrapping_sub(unsafe { (*b).length });
        if difference != 0 || a_length == 0 {
            return difference;
        }
        // SAFETY: as above.
        let a = unsafe { content(a) };
        // SAFETY: as above.
        let b = unsafe { content(b) };
        a.iter()
            .zip(b)
            .find(|(x, y)| x != y)
            .map_or(0, |(x, y)| c_int::from(*x) - c_int::from(*y))
    }
}

ffi_export! {
    /// The length of `obj`'s content octets (as `size_t`), or 0 for NULL.
    ///
    /// # Safety
    /// `obj` is NULL or a live object.
    pub unsafe extern "C" fn OBJ_length(obj: *const ASN1_OBJECT) -> usize
    where failure = 0, library = ERR_LIB_OBJ
    {
        let object: *const Object = obj.cast();
        if object.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let length = unsafe { (*object).length };
        // C's conversion of the int to size_t.
        isize::try_from(length).map_or(0, isize::cast_unsigned)
    }
}

ffi_export! {
    /// `obj`'s content octets, or NULL.
    ///
    /// # Safety
    /// `obj` is NULL or a live object.
    pub unsafe extern "C" fn OBJ_get0_data(obj: *const ASN1_OBJECT) -> *const u8
    where failure = ptr::null(), library = ERR_LIB_OBJ
    {
        let object: *const Object = obj.cast();
        // SAFETY: the caller's guarantee.
        if object.is_null() { ptr::null() } else { unsafe { (*object).data } }
    }
}

/// The byte at `i` of the line buffer, or NUL past its end.
fn byte_at(buf: &[u8], i: usize) -> u8 {
    buf.get(i).copied().unwrap_or(0)
}

/// `ossl_isspace`.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

ffi_export! {
    /// Creates an object (`OBJ_create`) for each line of `in`: dotted numbers, then optionally
    /// a short name and a long name, separated by whitespace. Stops at the first line that
    /// doesn't start with a letter or digit, or fails; returns how many it created.
    ///
    /// As in OpenSSL, the line buffer is 512 bytes and the long name of a line without one is
    /// what was left in the buffer where the last long name was.
    ///
    /// # Safety
    /// `in` is NULL or a live BIO.
    pub unsafe extern "C" fn OBJ_create_objects(in_: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_OBJ
    {
        let mut buf = [0u8; 512];
        let mut long: Option<usize> = None;
        let mut created = 0;
        // The C string starting at `at` in the buffer (bounded by it).
        let string = |buf: &[u8], at: usize| -> Vec<u8> {
            let rest = buf.get(at..).unwrap_or(&[]);
            let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
            rest.get(..end).unwrap_or(&[]).to_vec()
        };
        loop {
            // SAFETY: the caller's guarantee; `buf` holds 512 bytes.
            let got = unsafe { crate::bio::BIO_gets(in_, buf.as_mut_ptr().cast(), 512) };
            let Some(last) = usize::try_from(got).ok().and_then(|n| n.checked_sub(1)) else {
                return created;
            };
            if let Some(byte) = buf.get_mut(last) {
                *byte = 0;
            }
            if !buf.first().is_some_and(u8::is_ascii_alphanumeric) {
                return created;
            }
            let mut s = 0usize;
            while byte_at(&buf, s).is_ascii_digit() || byte_at(&buf, s) == b'.' {
                s += 1;
            }
            let mut short: Option<usize> = None;
            if byte_at(&buf, s) != 0 {
                if let Some(byte) = buf.get_mut(s) {
                    *byte = 0;
                }
                s += 1;
                while is_space(byte_at(&buf, s)) {
                    s += 1;
                }
                if byte_at(&buf, s) != 0 {
                    short = Some(s);
                    let mut l = s;
                    while byte_at(&buf, l) != 0 && !is_space(byte_at(&buf, l)) {
                        l += 1;
                    }
                    long = None;
                    if byte_at(&buf, l) != 0 {
                        if let Some(byte) = buf.get_mut(l) {
                            *byte = 0;
                        }
                        l += 1;
                        while is_space(byte_at(&buf, l)) {
                            l += 1;
                        }
                        if byte_at(&buf, l) != 0 {
                            long = Some(l);
                        }
                    }
                }
            }
            if byte_at(&buf, 0) == 0 {
                return created;
            }
            let oid = CString::new(string(&buf, 0)).unwrap_or_default();
            let short = short.and_then(|i| CString::new(string(&buf, i)).ok());
            let long = long.and_then(|i| CString::new(string(&buf, i)).ok());
            let as_ptr = |s: &Option<CString>| s.as_ref().map_or(ptr::null(), |s| s.as_ptr());
            // SAFETY: NUL-terminated strings or NULL.
            if unsafe { OBJ_create(oid.as_ptr(), as_ptr(&short), as_ptr(&long)) } == 0 {
                return created;
            }
            created += 1;
        }
    }
}

/// OpenSSL's binary search (`ossl_bsearch`) over `num` elements of `size` bytes at `base`.
///
/// # Safety
/// `base` holds `num` elements of `size` bytes that `cmp` accepts, with `key`.
unsafe fn bsearch(
    key: *const c_void,
    base: *const c_void,
    num: c_int,
    size: c_int,
    cmp: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
    flags: c_int,
) -> *const c_void {
    let element = |i: c_int| -> *const c_void {
        let offset = isize::try_from(i64::from(i).wrapping_mul(i64::from(size))).unwrap_or(0);
        base.cast::<u8>().wrapping_offset(offset).cast()
    };
    if num == 0 {
        return ptr::null();
    }
    let (mut low, mut high, mut i, mut c) = (0, num, 0, 0);
    let mut found: *const c_void = ptr::null();
    while low < high {
        i = low.wrapping_add(high.wrapping_sub(low) / 2);
        found = element(i);
        // SAFETY: an element of the caller's array.
        c = unsafe { cmp(key, found) };
        match c.cmp(&0) {
            core::cmp::Ordering::Less => high = i,
            core::cmp::Ordering::Greater => low = i.wrapping_add(1),
            core::cmp::Ordering::Equal => break,
        }
    }
    if c != 0 && flags & OBJ_BSEARCH_VALUE_ON_NOMATCH == 0 {
        return ptr::null();
    }
    if c == 0 && flags & OBJ_BSEARCH_FIRST_VALUE_ON_MATCH != 0 {
        // SAFETY: elements before a match are in the caller's array.
        while i > 0 && unsafe { cmp(key, element(i.wrapping_sub(1))) } == 0 {
            i = i.wrapping_sub(1);
        }
        found = element(i);
    }
    found
}

ffi_export! {
    /// Binary search: an element of `base` (`num` of `size` bytes) that `cmp` finds equal to
    /// `key`, or NULL.
    ///
    /// # Safety
    /// `base` holds `num` elements of `size` bytes; `cmp` accepts `key` and each of them.
    pub unsafe extern "C" fn OBJ_bsearch_(key: *const c_void, base: *const c_void, num: c_int, size: c_int, cmp: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>) -> *const c_void
    where failure = ptr::null(), library = ERR_LIB_OBJ
    {
        // SAFETY: the caller's guarantee.
        unsafe { OBJ_bsearch_ex_(key, base, num, size, cmp, 0) }
    }
}

ffi_export! {
    /// `OBJ_bsearch_` with `OBJ_BSEARCH_VALUE_ON_NOMATCH` (where the search stopped, when
    /// nothing matches) and `OBJ_BSEARCH_FIRST_VALUE_ON_MATCH` (the first of equal elements).
    ///
    /// Unlike OpenSSL, a NULL `cmp` finds nothing rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// As for `OBJ_bsearch_`.
    pub unsafe extern "C" fn OBJ_bsearch_ex_(key: *const c_void, base: *const c_void, num: c_int, size: c_int, cmp: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>, flags: c_int) -> *const c_void
    where failure = ptr::null(), library = ERR_LIB_OBJ
    {
        let Some(cmp) = cmp else {
            return ptr::null();
        };
        // SAFETY: the caller's guarantee.
        unsafe { bsearch(key, base, num, size, cmp, flags) }
    }
}

ffi_export! {
    /// A new, empty, dynamic object.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_OBJECT_new() -> *mut ASN1_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        new_object().cast()
    }
}

ffi_export! {
    /// Frees `a` and what it owns if it is dynamic; built-in and added objects stay.
    ///
    /// # Safety
    /// `a` is NULL or a live object, not used afterwards if it is dynamic.
    pub unsafe extern "C" fn ASN1_OBJECT_free(a: *mut ASN1_OBJECT)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { free_object(a.cast()) }
    }
}

ffi_export! {
    /// A new dynamic object with NID `nid`, a copy of `len` bytes of content `data`, and copies
    /// of the names `sn` and `ln` (each may be NULL). NULL if `data` is NULL with a positive
    /// `len`.
    ///
    /// # Safety
    /// `data` is NULL or holds `len` bytes; `sn` and `ln` are NULL or NUL-terminated strings.
    pub unsafe extern "C" fn ASN1_OBJECT_create(nid: c_int, data: *mut u8, len: c_int, sn: *const c_char, ln: *const c_char) -> *mut ASN1_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        let template = Object { sn, ln, nid, length: len, data, flags: FLAGS_ALL_DYNAMIC };
        // SAFETY: the caller's guarantee about what the template points to.
        unsafe { dup(&raw const template) }.cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_objects_are_shared_and_named() {
        // SAFETY: no preconditions.
        let sha256 = unsafe { OBJ_nid2obj(672) };
        // SAFETY: as above.
        let again = unsafe { OBJ_nid2obj(672) };
        assert_eq!(sha256, again);
        // SAFETY: a live object.
        assert_eq!(unsafe { OBJ_obj2nid(sha256) }, 672);
        // SAFETY: as above.
        let name = unsafe { OBJ_nid2sn(672) };
        // SAFETY: a name is a string.
        let name = unsafe { CStr::from_ptr(name) };
        assert_eq!(name, c"SHA256");
        // SAFETY: freeing a built-in object does nothing.
        unsafe { ASN1_OBJECT_free(sha256) };
        // SAFETY: still live.
        assert_eq!(unsafe { OBJ_length(sha256) }, 9);
    }

    #[test]
    fn negative_buffer_lengths_and_null_arguments_are_safe() {
        let mut buf = [b'x'; 4];
        // SAFETY: no preconditions.
        let sha256 = unsafe { OBJ_nid2obj(672) };
        // SAFETY: a negative length writes nothing to the 4-byte buffer.
        let written = unsafe { OBJ_obj2txt(buf.as_mut_ptr().cast(), -5, sha256, 0) };
        assert_eq!((written, buf), (6, [b'x'; 4]));
        // SAFETY: NULL arguments are refused.
        assert_eq!(unsafe { OBJ_sn2nid(ptr::null()) }, NID_undef);
        // SAFETY: as above.
        assert_eq!(unsafe { OBJ_ln2nid(ptr::null()) }, NID_undef);
        // SAFETY: as above.
        assert!(unsafe { OBJ_txt2obj(ptr::null(), 0) }.is_null());
        // SAFETY: as above.
        let encoded = unsafe { a2d_ASN1_OBJECT(ptr::null_mut(), 0, ptr::null(), -1) };
        assert_eq!(encoded, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { OBJ_cmp(ptr::null(), sha256) }, -1);
        // SAFETY: as above.
        assert!(unsafe { OBJ_bsearch_(ptr::null(), ptr::null(), 3, 4, None) }.is_null());
    }

    #[test]
    fn adding_a_built_in_object_keeps_it() {
        // SAFETY: no preconditions.
        let cn = unsafe { OBJ_nid2obj(13) };
        // SAFETY: a built-in object, which stays as it is.
        assert_eq!(unsafe { OBJ_add_object(cn) }, 13);
        // SAFETY: still live and unchanged.
        assert_eq!(unsafe { (*cn.cast::<Object>()).flags }, 0);
    }
}
