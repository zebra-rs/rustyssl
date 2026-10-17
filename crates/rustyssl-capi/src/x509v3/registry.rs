//! The extension methods (`X509V3_EXT_add(3)`, `X509V3_get_d2i(3)`, `X509V3_EXT_print(3)`;
//! `v3_lib.c`, `v3_prn.c`, and `do_ext_i2d` of `v3_conf.c`): OpenSSL's built-in methods, one
//! for each extension of `standard_exts.h`, and the application's, found by NID; an
//! extension's value decoded, encoded, and printed through its method.
//!
//! As in OpenSSL:
//! - A built-in method is found first; an application's (`X509V3_EXT_add`, `_add_list`,
//!   `_add_alias`) only for a NID none has. `X509V3_EXT_cleanup` drops the application's,
//!   freeing the aliases.
//! - `X509V3_get_d2i` reports a repeated extension (`*crit` -2) when it isn't asked to go on
//!   from an index, and `X509V3_add1_i2d` follows its flags (append, replace, keep, delete).
//! - Printing goes through the method's `i2s`, `i2v` (one line or many), or `i2r`; an
//!   extension without a method, or that doesn't decode, prints as the flags say.
//!
//! The built-in methods of the extensions whose types come later in step 5.2 are there with
//! their NIDs, so the lookup answers as OpenSSL's does, and their functions abort when called
//! (AGENTS.md rule 10).

use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::ptr;
use std::sync::{LazyLock, Mutex, PoisonError};

use libc::FILE;
use rustyssl_abi::{
    BIO, BIO_NOCLOSE, ERR_LIB_X509V3, ERR_R_ASN1_LIB, ERR_R_CRYPTO_LIB, ERR_R_X509V3_LIB,
    NID_authority_key_identifier, NID_subject_key_identifier, NID_undef, X509_EXTENSION,
    X509_FLAG_EXTENSIONS_ONLY_KID, X509V3_ADD_APPEND, X509V3_ADD_DEFAULT, X509V3_ADD_DELETE,
    X509V3_ADD_KEEP_EXISTING, X509V3_ADD_OP_MASK, X509V3_ADD_REPLACE_EXISTING, X509V3_ADD_SILENT,
    X509V3_EXT_DEFAULT, X509V3_EXT_DUMP_UNKNOWN, X509V3_EXT_DYNAMIC, X509V3_EXT_ERROR_UNKNOWN,
    X509V3_EXT_METHOD, X509V3_EXT_MULTILINE, X509V3_EXT_PARSE_UNKNOWN, X509V3_EXT_UNKNOWN_MASK,
    X509V3_R_ERROR_CREATING_EXTENSION, X509V3_R_EXTENSION_EXISTS, X509V3_R_EXTENSION_NOT_FOUND,
    X509V3_R_UNKNOWN_EXTENSION, stack_st_CONF_VALUE, stack_st_X509_EXTENSION,
};

use crate::asn1::parse::ASN1_parse_dump;
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new};
use crate::asn1::text::ASN1_STRING_print;
use crate::asn1::tpl::decode::ASN1_item_d2i;
use crate::asn1::tpl::encode::ASN1_item_i2d;
use crate::asn1::tpl::free::ASN1_item_free;
use crate::bio::dump::BIO_dump_indent;
use crate::bio::file::BIO_new_fp;
use crate::bio::print::BIO_printf;
use crate::bio::{BIO_free, BIO_puts, BIO_write};
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::{OBJ_obj2nid, i2a_ASN1_OBJECT};
use crate::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_set, OPENSSL_sk_value,
};
use crate::x509::ext::{
    X509_EXTENSION_create_by_NID, X509_EXTENSION_free, X509_EXTENSION_get_critical,
    X509_EXTENSION_get_data, X509_EXTENSION_get_object, X509v3_get_ext_by_NID,
};

/// A method in a static.
#[repr(transparent)]
pub(crate) struct Method(pub(crate) X509V3_EXT_METHOD);

// SAFETY: a built-in method is immutable; its `usr_data` points to an immutable static table.
unsafe impl Sync for Method {}

/// A method with only its NID, flags, and functions: what `X509V3_EXT_METHOD`'s initialisers
/// in OpenSSL's sources leave as NULL stays NULL.
pub(crate) const fn method(nid: c_int, flags: c_int) -> X509V3_EXT_METHOD {
    X509V3_EXT_METHOD {
        ext_nid: nid,
        ext_flags: flags,
        it: None,
        ext_new: None,
        ext_free: None,
        d2i: None,
        i2d: None,
        i2s: None,
        s2i: None,
        i2v: None,
        v2i: None,
        i2r: None,
        r2i: None,
        usr_data: ptr::null_mut(),
    }
}

/// The built-in methods, sorted by NID (`standard_exts`).
static STANDARD: LazyLock<Vec<&'static Method>> = LazyLock::new(|| {
    let mut all: Vec<&'static Method> = super::standard::methods().collect();
    all.sort_by_key(|m| m.0.ext_nid);
    all
});

/// An application's method (`ext_list`), which it keeps (or, for an alias, that's ours).
struct AppMethod(*mut X509V3_EXT_METHOD);

// SAFETY: the pointers are only handed back; what they point to is the application's to keep
// alive and unchanged, as OpenSSL requires.
unsafe impl Send for AppMethod {}

/// The application's methods, in the order added.
static APP: Mutex<Vec<AppMethod>> = Mutex::new(Vec::new());

/// The built-in method for `nid`, if there's one.
pub(crate) fn standard(nid: c_int) -> Option<&'static Method> {
    let all = &*STANDARD;
    all.binary_search_by_key(&nid, |m| m.0.ext_nid)
        .ok()
        .and_then(|i| all.get(i).copied())
}

ffi_export! {
    /// Adds an application's method (which it keeps alive): 1, or 0.
    ///
    /// # Safety
    /// `ext` is a method that outlives its use, or one `X509V3_EXT_add_alias` made.
    pub unsafe extern "C" fn X509V3_EXT_add(ext: *mut X509V3_EXT_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        if ext.is_null() {
            err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, "X509V3_EXT_add");
            return 0;
        }
        APP.lock().unwrap_or_else(PoisonError::into_inner).push(AppMethod(ext));
        1
    }
}

ffi_export! {
    /// The method for `nid` (a built-in one first, then the application's), or NULL.
    ///
    /// # Safety
    /// The application's methods are live.
    pub unsafe extern "C" fn X509V3_EXT_get_nid(nid: c_int) -> *const X509V3_EXT_METHOD
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        if nid < 0 {
            return ptr::null();
        }
        if let Some(m) = standard(nid) {
            return &raw const m.0;
        }
        let app = APP.lock().unwrap_or_else(PoisonError::into_inner);
        app.iter()
            // SAFETY: the application's live methods.
            .find(|m| unsafe { (*m.0).ext_nid } == nid)
            .map_or(ptr::null(), |m| m.0.cast_const())
    }
}

ffi_export! {
    /// The method for the extension's object, or NULL.
    ///
    /// # Safety
    /// `ext` is NULL or a live extension.
    pub unsafe extern "C" fn X509V3_EXT_get(ext: *mut X509_EXTENSION) -> *const X509V3_EXT_METHOD
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let obj = unsafe { X509_EXTENSION_get_object(ext) };
        // SAFETY: its object, or NULL.
        let nid = unsafe { OBJ_obj2nid(obj) };
        if nid == NID_undef {
            return ptr::null();
        }
        // SAFETY: as above.
        unsafe { X509V3_EXT_get_nid(nid) }
    }
}

ffi_export! {
    /// Adds each method of a list ended by one with NID -1: 1, or 0.
    ///
    /// # Safety
    /// `extlist` is a live list of methods, ended so, that outlives its use.
    pub unsafe extern "C" fn X509V3_EXT_add_list(extlist: *mut X509V3_EXT_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        let mut m = extlist;
        // SAFETY: the caller's guarantee: within the list, up to its end.
        while unsafe { (*m).ext_nid } != -1 {
            // SAFETY: a method of the list.
            if unsafe { X509V3_EXT_add(m) } == 0 {
                return 0;
            }
            m = m.wrapping_add(1);
        }
        1
    }
}

ffi_export! {
    /// Adds a copy of `nid_from`'s method for `nid_to`: 1, or 0 with
    /// `X509V3_R_EXTENSION_NOT_FOUND`.
    ///
    /// # Safety
    /// The application's methods are live.
    pub unsafe extern "C" fn X509V3_EXT_add_alias(nid_to: c_int, nid_from: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let ext = unsafe { X509V3_EXT_get_nid(nid_from) };
        if ext.is_null() {
            err::raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_NOT_FOUND, "X509V3_EXT_add_alias");
            return 0;
        }
        let tmpext: *mut X509V3_EXT_METHOD = mem::alloc(size_of::<X509V3_EXT_METHOD>()).cast();
        if tmpext.is_null() {
            return 0;
        }
        // SAFETY: a live method.
        let mut copy = unsafe { ext.read() };
        copy.ext_nid = nid_to;
        copy.ext_flags |= X509V3_EXT_DYNAMIC;
        // SAFETY: room for a method.
        unsafe { tmpext.write(copy) };
        // SAFETY: the copy, freed by `X509V3_EXT_cleanup`.
        if unsafe { X509V3_EXT_add(tmpext) } == 0 {
            // SAFETY: allocated above.
            unsafe { mem::release(tmpext.cast()) };
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Drops the application's methods, freeing the copies `X509V3_EXT_add_alias` made.
    ///
    /// # Safety
    /// No method dropped is in use.
    pub unsafe extern "C" fn X509V3_EXT_cleanup()
    where failure = (), library = ERR_LIB_X509V3
    {
        let all = core::mem::take(&mut *APP.lock().unwrap_or_else(PoisonError::into_inner));
        for m in all {
            // SAFETY: the application's live method, or our copy.
            if unsafe { (*m.0).ext_flags } & X509V3_EXT_DYNAMIC != 0 {
                // SAFETY: allocated by `X509V3_EXT_add_alias`.
                unsafe { mem::release(m.0.cast()) };
            }
        }
    }
}

ffi_export! {
    /// Does nothing: the built-in methods are always there. Returns 1.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509V3_add_standard_extensions() -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        1
    }
}

/// Decodes `len` octets at `p` with the method: its item, or its `d2i`.
///
/// # Safety
/// `method` is a live method; `p` holds `len` readable octets.
pub(crate) unsafe fn method_d2i(
    method: &X509V3_EXT_METHOD,
    p: &mut *const u8,
    len: c_int,
) -> *mut c_void {
    let len = core::ffi::c_long::from(len);
    if let Some(it) = method.it {
        // SAFETY: the method's item.
        let it = unsafe { it() };
        // SAFETY: the caller's octets.
        return unsafe { ASN1_item_d2i(ptr::null_mut(), p, len, it) }.cast();
    }
    match method.d2i {
        // SAFETY: the method's function, given the caller's octets.
        Some(d2i) => unsafe { d2i(ptr::null_mut(), p, len) },
        None => ptr::null_mut(),
    }
}

/// Frees a value the method decoded: through its item, or its `ext_free`.
///
/// # Safety
/// `method` is a live method; `value` is NULL or one of its values.
pub(crate) unsafe fn method_free(method: &X509V3_EXT_METHOD, value: *mut c_void) {
    if let Some(it) = method.it {
        // SAFETY: the method's item.
        let it = unsafe { it() };
        // SAFETY: a value of the item, or NULL.
        unsafe { ASN1_item_free(value.cast(), it) };
    } else if let Some(f) = method.ext_free {
        // SAFETY: the method's function, given its value.
        unsafe { f(value) };
    }
}

ffi_export! {
    /// The extension's value decoded with its method (for the caller to free), or NULL.
    ///
    /// # Safety
    /// `ext` is NULL or a live extension.
    pub unsafe extern "C" fn X509V3_EXT_d2i(ext: *mut X509_EXTENSION) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let method = unsafe { X509V3_EXT_get(ext) };
        // SAFETY: a live method, or NULL.
        let Some(m) = (unsafe { method.as_ref() }) else { return ptr::null_mut() };
        // SAFETY: the caller's extension.
        let data = unsafe { X509_EXTENSION_get_data(ext) };
        // SAFETY: its value.
        let Some(v) = (unsafe { data.as_ref() }) else { return ptr::null_mut() };
        let mut p = v.data.cast_const();
        // SAFETY: the value's `length` octets.
        unsafe { method_d2i(m, &mut p, v.length) }
    }
}

ffi_export! {
    /// The value of the extension of `nid` in `x`, decoded (for the caller to free), or NULL:
    /// with `idx`, the first after `*idx` (its index into `*idx`, -1 for none); without, the only
    /// one (`*crit` -2 if there are more). `*crit` is its criticality, or -1 for none.
    ///
    /// # Safety
    /// `x` is NULL or a live stack of extensions; `crit` and `idx` are NULL or valid.
    pub unsafe extern "C" fn X509V3_get_d2i(x: *const stack_st_X509_EXTENSION, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        let set = |p: *mut c_int, v: c_int| {
            if !p.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { p.write(v) };
            }
        };
        if x.is_null() {
            set(idx, -1);
            set(crit, -1);
            return ptr::null_mut();
        }
        let lastpos = if idx.is_null() {
            0
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { idx.read() }.saturating_add(1).max(0)
        };
        let mut found: *mut X509_EXTENSION = ptr::null_mut();
        // SAFETY: the caller's stack.
        let n = unsafe { OPENSSL_sk_num(x.cast()) };
        for i in lastpos..n {
            // SAFETY: an index within the stack.
            let ex = unsafe { OPENSSL_sk_value(x.cast(), i) }.cast::<X509_EXTENSION>();
            // SAFETY: an extension of the stack.
            let obj = unsafe { X509_EXTENSION_get_object(ex) };
            // SAFETY: its object.
            if unsafe { OBJ_obj2nid(obj) } != nid {
                continue;
            }
            if !idx.is_null() {
                set(idx, i);
                found = ex;
                break;
            }
            if !found.is_null() {
                set(crit, -2);
                return ptr::null_mut();
            }
            found = ex;
        }
        if found.is_null() {
            set(idx, -1);
            set(crit, -1);
            return ptr::null_mut();
        }
        // SAFETY: the extension found.
        set(crit, unsafe { X509_EXTENSION_get_critical(found) });
        // SAFETY: as above.
        unsafe { X509V3_EXT_d2i(found) }
    }
}

/// `do_ext_i2d`: an extension of `ext_nid` whose value is `ext_struc` encoded with the method,
/// or NULL.
///
/// # Safety
/// `method` is a live method; `ext_struc` is a value of it.
pub(crate) unsafe fn do_ext_i2d(
    method: &X509V3_EXT_METHOD,
    ext_nid: c_int,
    crit: c_int,
    ext_struc: *mut c_void,
) -> *mut X509_EXTENSION {
    const F: &str = "do_ext_i2d";
    let mut ext_der: *mut u8 = ptr::null_mut();
    let ext_len = if let Some(it) = method.it {
        // SAFETY: the method's item.
        let it = unsafe { it() };
        // SAFETY: a value of the item; a place for the encoding.
        let n = unsafe { ASN1_item_i2d(ext_struc.cast(), &raw mut ext_der, it) };
        if n < 0 {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
            return ptr::null_mut();
        }
        n
    } else {
        let Some(i2d) = method.i2d else {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
            return ptr::null_mut();
        };
        // SAFETY: the method's function, given its value.
        let n = unsafe { i2d(ext_struc, ptr::null_mut()) };
        let Ok(size) = usize::try_from(n) else {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
            return ptr::null_mut();
        };
        if size == 0 {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
            return ptr::null_mut();
        }
        ext_der = mem::alloc(size).cast();
        if ext_der.is_null() {
            return ptr::null_mut();
        }
        let mut p = ext_der;
        // SAFETY: as above; room for the encoding.
        unsafe { i2d(ext_struc, &raw mut p) };
        n
    };
    // SAFETY: no preconditions.
    let oct = unsafe { ASN1_OCTET_STRING_new() };
    // SAFETY: the new string, or NULL.
    let Some(o) = (unsafe { oct.as_mut() }) else {
        err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
        // SAFETY: the encoding.
        unsafe { mem::release(ext_der.cast()) };
        return ptr::null_mut();
    };
    o.data = ext_der;
    o.length = ext_len;
    // SAFETY: the string, copied into the extension.
    let ext = unsafe { X509_EXTENSION_create_by_NID(ptr::null_mut(), ext_nid, crit, oct) };
    if ext.is_null() {
        err::raise(ERR_LIB_X509V3, ERR_R_X509V3_LIB, F);
    }
    // SAFETY: made above, with the encoding.
    unsafe { ASN1_OCTET_STRING_free(oct) };
    ext
}

ffi_export! {
    /// An extension of `ext_nid` whose value is `ext_struc` encoded with the NID's method, or
    /// NULL (`X509V3_R_UNKNOWN_EXTENSION` without one).
    ///
    /// # Safety
    /// `ext_struc` is a value of the NID's method.
    pub unsafe extern "C" fn X509V3_EXT_i2d(ext_nid: c_int, crit: c_int, ext_struc: *mut c_void) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: no preconditions.
        let method = unsafe { X509V3_EXT_get_nid(ext_nid) };
        // SAFETY: a live method, or NULL.
        let Some(m) = (unsafe { method.as_ref() }) else {
            err::raise(ERR_LIB_X509V3, X509V3_R_UNKNOWN_EXTENSION, "X509V3_EXT_i2d");
            return ptr::null_mut();
        };
        // SAFETY: the caller's guarantee.
        unsafe { do_ext_i2d(m, ext_nid, crit, ext_struc) }
    }
}

/// `X509_EXTENSION_free` as a stack's free function.
pub(crate) unsafe extern "C" fn free_ext(e: *mut c_void) {
    // SAFETY: an extension of the stack, which the stack owned.
    unsafe { X509_EXTENSION_free(e.cast()) };
}

ffi_export! {
    /// Adds the extension of `nid` with `value` (encoded) to `*x`, as `flags` say: append,
    /// replace or keep or delete an existing one, or (the default) refuse one that exists.
    /// 1, 0 with the reason (none with `X509V3_ADD_SILENT`), or -1 if memory runs out.
    ///
    /// # Safety
    /// `x` holds NULL or a live stack of extensions; `value` is a value of the NID's method.
    pub unsafe extern "C" fn X509V3_add1_i2d(x: *mut *mut stack_st_X509_EXTENSION, nid: c_int, value: *mut c_void, crit: c_int, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        const F: &str = "X509V3_add1_i2d";
        if x.is_null() {
            return 0;
        }
        let op = flags & X509V3_ADD_OP_MASK.cast_unsigned();
        let op_is = |o: core::ffi::c_long| op == o.cast_unsigned();
        let fail = |reason: c_int| {
            if flags & c_ulong::from(X509V3_ADD_SILENT.cast_unsigned()) == 0 {
                err::raise(ERR_LIB_X509V3, reason, F);
            }
            0
        };
        // SAFETY: the caller's guarantee.
        let sk = unsafe { x.read() };
        let extidx = if op_is(X509V3_ADD_APPEND) {
            -1
        } else {
            // SAFETY: the caller's stack, or NULL.
            unsafe { X509v3_get_ext_by_NID(sk, nid, -1) }
        };
        if extidx >= 0 {
            if op_is(X509V3_ADD_KEEP_EXISTING) {
                return 1;
            }
            if op_is(X509V3_ADD_DEFAULT) {
                return fail(X509V3_R_EXTENSION_EXISTS);
            }
            if op_is(X509V3_ADD_DELETE) {
                // SAFETY: an index within the stack.
                let gone = unsafe { OPENSSL_sk_delete(sk.cast(), extidx) };
                if gone.is_null() {
                    return -1;
                }
                // SAFETY: taken out, ours to free.
                unsafe { X509_EXTENSION_free(gone.cast()) };
                return 1;
            }
        } else if op_is(X509V3_ADD_REPLACE_EXISTING) || op_is(X509V3_ADD_DELETE) {
            return fail(X509V3_R_EXTENSION_NOT_FOUND);
        }
        // SAFETY: the caller's guarantee.
        let ext = unsafe { X509V3_EXT_i2d(nid, crit, value) };
        if ext.is_null() {
            err::raise(ERR_LIB_X509V3, X509V3_R_ERROR_CREATING_EXTENSION, F);
            return 0;
        }
        if extidx >= 0 {
            // SAFETY: an index within the stack.
            let old = unsafe { OPENSSL_sk_value(sk.cast(), extidx) };
            // SAFETY: the extension replaced.
            unsafe { X509_EXTENSION_free(old.cast()) };
            // SAFETY: as above; the new extension, which the stack takes.
            if unsafe { OPENSSL_sk_set(sk.cast(), extidx, ext.cast()) }.is_null() {
                return -1;
            }
            return 1;
        }
        let ret = if sk.is_null() {
            // SAFETY: no preconditions.
            unsafe { OPENSSL_sk_new_null() }.cast()
        } else {
            sk
        };
        // SAFETY: the stack, or NULL; the new extension, which it takes.
        if ret.is_null() || unsafe { OPENSSL_sk_push(ret.cast(), ext.cast()) } == 0 {
            if ret != sk {
                // SAFETY: made above, or NULL.
                unsafe { OPENSSL_sk_pop_free(ret.cast(), Some(free_ext)) };
            }
            // SAFETY: made above.
            unsafe { X509_EXTENSION_free(ext) };
            return -1;
        }
        // SAFETY: the caller's slot.
        unsafe { x.write(ret) };
        1
    }
}

/// `BIO_printf(out, "%*s", indent, "")`.
///
/// # Safety
/// `out` is a live BIO.
pub(crate) unsafe fn indent_to(out: *mut BIO, indent: c_int) -> c_int {
    // SAFETY: the caller's BIO; a static format and its arguments.
    unsafe { BIO_printf(out, c"%*s".as_ptr(), indent, c"".as_ptr()) }
}

ffi_export! {
    /// Prints a list of `CONF_VALUE`s at `indent`: one per line for `ml`, otherwise separated by
    /// commas, as `name:value`, `name`, or `value`; `<EMPTY>` for none.
    ///
    /// # Safety
    /// `out` is a live BIO; `val` is NULL or a live stack of `CONF_VALUE`s.
    pub unsafe extern "C" fn X509V3_EXT_val_prn(out: *mut BIO, val: *mut stack_st_CONF_VALUE, indent: c_int, ml: c_int)
    where failure = (), library = ERR_LIB_X509V3
    {
        if val.is_null() {
            return;
        }
        // SAFETY: the caller's stack.
        let n = unsafe { OPENSSL_sk_num(val.cast()) };
        if ml == 0 || n == 0 {
            // SAFETY: the caller's BIO.
            unsafe { indent_to(out, indent) };
            if n == 0 {
                // SAFETY: as above.
                unsafe { BIO_puts(out, c"<EMPTY>\n".as_ptr()) };
            }
        }
        for i in 0..n {
            if ml != 0 {
                if i > 0 {
                    // SAFETY: as above.
                    unsafe { BIO_puts(out, c"\n".as_ptr()) };
                }
                // SAFETY: as above.
                unsafe { indent_to(out, indent) };
            } else if i > 0 {
                // SAFETY: as above.
                unsafe { BIO_puts(out, c", ".as_ptr()) };
            }
            // SAFETY: an index within the stack; a `CONF_VALUE`.
            let v = unsafe { OPENSSL_sk_value(val.cast(), i) }.cast::<rustyssl_abi::CONF_VALUE>();
            // SAFETY: as above.
            let Some(v) = (unsafe { v.as_ref() }) else { continue };
            if v.name.is_null() {
                // SAFETY: its value, a string.
                unsafe { BIO_puts(out, v.value) };
            } else if v.value.is_null() {
                // SAFETY: its name, a string.
                unsafe { BIO_puts(out, v.name) };
            } else {
                // SAFETY: as above; a static format and its strings.
                unsafe { BIO_printf(out, c"%s:%s".as_ptr(), v.name, v.value) };
            }
        }
    }
}

/// `unknown_ext_print`: an extension without a method (or, `supported`, one that didn't
/// decode), as `flag` says: nothing (0), `<Not Supported>`/`<Parse Error>`, the octets parsed,
/// or a dump.
///
/// # Safety
/// `out` is a live BIO; `ext` holds `extlen` readable octets.
unsafe fn unknown_ext_print(
    out: *mut BIO,
    ext: *const u8,
    extlen: c_int,
    flag: c_ulong,
    indent: c_int,
    supported: bool,
) -> c_int {
    let mode = flag & X509V3_EXT_UNKNOWN_MASK.cast_unsigned();
    let is = |m: core::ffi::c_long| mode == m.cast_unsigned();
    if is(core::ffi::c_long::from(X509V3_EXT_DEFAULT)) {
        return 0;
    }
    if is(X509V3_EXT_ERROR_UNKNOWN) {
        let text = if supported {
            c"<Parse Error>"
        } else {
            c"<Not Supported>"
        };
        // SAFETY: the caller's BIO; a static format and its arguments.
        unsafe { BIO_printf(out, c"%*s%s".as_ptr(), indent, c"".as_ptr(), text.as_ptr()) };
        return 1;
    }
    if is(X509V3_EXT_PARSE_UNKNOWN) {
        // SAFETY: the caller's octets.
        return c_int::from(
            unsafe { ASN1_parse_dump(out, ext, core::ffi::c_long::from(extlen), indent, -1) } > 0,
        );
    }
    if is(X509V3_EXT_DUMP_UNKNOWN) {
        // SAFETY: as above.
        return c_int::from(unsafe { BIO_dump_indent(out, ext.cast(), extlen, indent) } > 0);
    }
    1
}

/// `X509V3_conf_free` as a stack's free function.
unsafe extern "C" fn free_conf(c: *mut c_void) {
    // SAFETY: a `CONF_VALUE` of the stack, which the stack owned.
    unsafe { super::X509V3_conf_free(c.cast()) };
}

ffi_export! {
    /// Prints the extension's value at `indent` through its method; one without a method, or
    /// that doesn't decode, as `flag` says. 1, or 0 if nothing was printed.
    ///
    /// # Safety
    /// `out` is a live BIO; `ext` is a live extension.
    pub unsafe extern "C" fn X509V3_EXT_print(out: *mut BIO, ext: *mut X509_EXTENSION, flag: c_ulong, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let data = unsafe { X509_EXTENSION_get_data(ext) };
        // SAFETY: its value.
        let Some(v) = (unsafe { data.as_ref() }) else { return 0 };
        let mut p = v.data.cast_const();
        let extlen = v.length;
        // SAFETY: as above.
        let method = unsafe { X509V3_EXT_get(ext) };
        // SAFETY: a live method, or NULL.
        let Some(m) = (unsafe { method.as_ref() }) else {
            // SAFETY: the value's octets.
            return unsafe { unknown_ext_print(out, p, extlen, flag, indent, false) };
        };
        // SAFETY: as above.
        let ext_str = unsafe { method_d2i(m, &mut p, extlen) };
        if ext_str.is_null() {
            // SAFETY: as above.
            return unsafe { unknown_ext_print(out, p, extlen, flag, indent, true) };
        }
        let mut ok = 1;
        if let Some(i2s) = m.i2s {
            // SAFETY: the method's function, given its value.
            let value = unsafe { i2s(method, ext_str) };
            if value.is_null() {
                ok = 0;
            } else {
                // SAFETY: the caller's BIO; a static format and its arguments.
                unsafe { BIO_printf(out, c"%*s%s".as_ptr(), indent, c"".as_ptr(), value) };
                // SAFETY: from the method, in C memory.
                unsafe { mem::release(value.cast()) };
            }
        } else if let Some(i2v) = m.i2v {
            // SAFETY: as above.
            let nval = unsafe { i2v(method, ext_str, ptr::null_mut()) };
            if nval.is_null() {
                ok = 0;
            } else {
                let ml = c_int::from(m.ext_flags & X509V3_EXT_MULTILINE != 0);
                // SAFETY: the caller's BIO; the method's list.
                unsafe { X509V3_EXT_val_prn(out, nval, indent, ml) };
                // SAFETY: the list, with its entries.
                unsafe { OPENSSL_sk_pop_free(nval.cast(), Some(free_conf)) };
            }
        } else if let Some(i2r) = m.i2r {
            // SAFETY: as above.
            ok = c_int::from(unsafe { i2r(method, ext_str, out, indent) } != 0);
        } else {
            ok = 0;
        }
        // SAFETY: the method's value.
        unsafe { method_free(m, ext_str) };
        ok
    }
}

ffi_export! {
    /// [`X509V3_EXT_print`] to a `FILE`.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `ext` is a live extension.
    pub unsafe extern "C" fn X509V3_EXT_print_fp(fp: *mut FILE, ext: *mut X509_EXTENSION, flag: c_int, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let b = unsafe { BIO_new_fp(fp, BIO_NOCLOSE) };
        if b.is_null() {
            return 0;
        }
        // As OpenSSL's, the flag's sign extends.
        let flag = c_ulong::from_ne_bytes(core::ffi::c_long::from(flag).to_ne_bytes());
        // SAFETY: the new BIO; the caller's extension.
        let ret = unsafe { X509V3_EXT_print(b, ext, flag, indent) };
        // SAFETY: made above.
        unsafe { BIO_free(b) };
        ret
    }
}

ffi_export! {
    /// Prints the extensions under `title` (if given; indented 4 more), each as its object, a
    /// `: critical` mark, and its value on the next lines (the octets when it can't print);
    /// only the key identifiers with `X509_FLAG_EXTENSIONS_ONLY_KID`. 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `title` is NULL or a string; `exts` is NULL or a live stack of
    /// extensions.
    pub unsafe extern "C" fn X509V3_extensions_print(bp: *mut BIO, title: *const c_char, exts: *const stack_st_X509_EXTENSION, flag: c_ulong, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let n = unsafe { OPENSSL_sk_num(exts.cast()) };
        if n <= 0 {
            return 1;
        }
        let mut indent = indent;
        if !title.is_null() {
            // SAFETY: the caller's BIO; a static format and its arguments.
            unsafe { BIO_printf(bp, c"%*s%s:\n".as_ptr(), indent, c"".as_ptr(), title) };
            indent = indent.saturating_add(4);
        }
        let only_kid = flag & X509_FLAG_EXTENSIONS_ONLY_KID.cast_unsigned() != 0;
        for i in 0..n {
            // SAFETY: an index within the stack.
            let ex = unsafe { OPENSSL_sk_value(exts.cast(), i) }.cast::<X509_EXTENSION>();
            // SAFETY: an extension of the stack.
            let obj = unsafe { X509_EXTENSION_get_object(ex) };
            // SAFETY: its object.
            let nid = unsafe { OBJ_obj2nid(obj) };
            if only_kid && nid != NID_subject_key_identifier && nid != NID_authority_key_identifier {
                continue;
            }
            // SAFETY: the caller's BIO.
            if indent != 0 && unsafe { indent_to(bp, indent) } <= 0 {
                return 0;
            }
            // SAFETY: as above; the object.
            unsafe { i2a_ASN1_OBJECT(bp, obj) };
            // SAFETY: the extension.
            let critical = unsafe { X509_EXTENSION_get_critical(ex) } != 0;
            let mark = if critical { c"critical" } else { c"" };
            // SAFETY: as above; a static format and its argument.
            if unsafe { BIO_printf(bp, c": %s\n".as_ptr(), mark.as_ptr()) } <= 0 {
                return 0;
            }
            // SAFETY: as above.
            if unsafe { X509V3_EXT_print(bp, ex, flag, indent.saturating_add(4)) } == 0 {
                // SAFETY: as above.
                unsafe { indent_to(bp, indent.saturating_add(4)) };
                // SAFETY: the extension.
                let data = unsafe { X509_EXTENSION_get_data(ex) };
                // SAFETY: its value.
                unsafe { ASN1_STRING_print(bp, data) };
            }
            // SAFETY: as above.
            if unsafe { BIO_write(bp, c"\n".as_ptr().cast(), 1) } <= 0 {
                return 0;
            }
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: a NULL method for `X509V3_EXT_add`, which OpenSSL keeps and later
    /// reads through, and a NULL list for `X509V3_add1_i2d`, which it reads through, fail.
    #[test]
    fn null_methods_and_lists_fail() {
        // SAFETY: NULL where OpenSSL keeps it.
        assert_eq!(unsafe { X509V3_EXT_add(ptr::null_mut()) }, 0);
        // SAFETY: NULL where OpenSSL dereferences it.
        let r = unsafe { X509V3_add1_i2d(ptr::null_mut(), NID_undef, ptr::null_mut(), 0, 0) };
        assert_eq!(r, 0);
        crate::err::take_all();
    }

    /// The built-in methods are one per NID, as OpenSSL's table is.
    #[test]
    fn one_builtin_method_per_nid() {
        let all = &*STANDARD;
        assert!(
            all.windows(2)
                .all(|w| w.first().map(|m| m.0.ext_nid) < w.get(1).map(|m| m.0.ext_nid))
        );
        assert_eq!(all.len(), 73);
    }
}
