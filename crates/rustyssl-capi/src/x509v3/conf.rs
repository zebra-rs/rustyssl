//! Extensions from configuration text (`v3_conf.c`, `X509V3_EXT_nconf(3)`): a name and a value
//! such as `basicConstraints = critical, CA:TRUE`, through the extension's method (its `v2i`
//! from a list or an `@section`, its `s2i`, or its `r2i`), or as raw `DER:` octets; and a
//! configuration section's extensions added to a certificate, request, or list.
//!
//! As OpenSSL's:
//! - `critical,` (then spaces) marks the extension critical.
//! - In a section, a subject key identifier listed after the authority key identifier is
//!   made first, since the authority's may need it.
//! - With `X509V3_CTX_REPLACE`, an extension replaces those of its type already there.
//! - `ASN1:` values are `ASN1_generate_v3`'s (`asn1/generate.rs`); the CRL
//!   functions come with CRLs (step 5.1e).

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;

use rustyssl_abi::{
    CONF, CONF_VALUE, ERR_LIB_X509V3, ERR_R_ASN1_LIB, ERR_R_PASSED_NULL_PARAMETER, NID_undef, X509,
    X509_CRL, X509_EXTENSION, X509_REQ, X509V3_CTX, X509V3_CTX_REPLACE,
    X509V3_R_ERROR_IN_EXTENSION, X509V3_R_EXTENSION_NAME_ERROR,
    X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED, X509V3_R_EXTENSION_VALUE_ERROR,
    X509V3_R_INVALID_EXTENSION_STRING, X509V3_R_NO_CONFIG_DATABASE, X509V3_R_UNKNOWN_EXTENSION,
    X509V3_R_UNKNOWN_EXTENSION_NAME, lhash_st_CONF_VALUE, stack_st_CONF_VALUE,
    stack_st_X509_EXTENSION,
};

use super::ctx::{X509V3_set_ctx, X509V3_set_nconf};
use super::registry::{X509V3_EXT_get_nid, do_ext_i2d};
use super::{X509V3_conf_free, X509V3_parse_list};
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new};
use crate::asn1::tpl::free::ASN1_item_free;
use crate::conf::{CONF_set_nconf, NCONF_free, NCONF_get_section, NCONF_new};
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::{ASN1_OBJECT_free, OBJ_nid2sn, OBJ_sn2nid, OBJ_txt2obj};
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value};
use crate::string::OPENSSL_hexstr2buf;
use crate::x509::cert::cert_of;
use crate::x509::ext::{
    X509_EXTENSION_create_by_OBJ, X509_EXTENSION_free, X509_EXTENSION_get_object, X509v3_add_ext,
    X509v3_delete_ext, X509v3_get_ext_by_OBJ,
};
use crate::x509::req::X509_REQ_add_extensions;

/// A C string's bytes, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a C string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) }.to_bytes())
}

/// `ossl_isspace`.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `p` after `prefix` and any spaces, or `None` without the prefix.
///
/// # Safety
/// `p` is a C string.
unsafe fn skip_prefix(p: *const c_char, prefix: &[u8]) -> Option<*const c_char> {
    // SAFETY: the caller's guarantee.
    let t = unsafe { text(p) }?;
    let rest = t.strip_prefix(prefix)?;
    let spaces = rest.iter().take_while(|&&c| is_space(c)).count();
    let skip = t.len().checked_sub(rest.len())?.checked_add(spaces)?;
    // SAFETY: within the string (its length is at least `skip`).
    Some(unsafe { p.add(skip) })
}

/// `v3_check_critical`: whether the value starts `critical,` (then skipped, with spaces).
///
/// # Safety
/// `*value` is a C string.
unsafe fn check_critical(value: &mut *const c_char) -> c_int {
    // SAFETY: the caller's guarantee.
    match unsafe { skip_prefix(*value, b"critical,") } {
        Some(p) => {
            *value = p;
            1
        }
        None => 0,
    }
}

/// `v3_check_generic`: 1 for `DER:`, 2 for `ASN1:` (then skipped, with spaces), or 0.
///
/// # Safety
/// `*value` is a C string.
unsafe fn check_generic(value: &mut *const c_char) -> c_int {
    for (prefix, kind) in [(&b"DER:"[..], 1), (b"ASN1:", 2)] {
        // SAFETY: the caller's guarantee.
        if let Some(p) = unsafe { skip_prefix(*value, prefix) } {
            *value = p;
            return kind;
        }
    }
    0
}

/// `name=…, value=…`-style error data: the pieces, a NULL string as `<NULL>`.
fn data(pieces: &[(&str, Option<&[u8]>)], sep: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for (i, (label, s)) in pieces.iter().enumerate() {
        if i > 0 {
            v.extend_from_slice(sep.as_bytes());
        }
        v.extend_from_slice(label.as_bytes());
        v.push(b'=');
        v.extend_from_slice(s.unwrap_or(b"<NULL>"));
    }
    v
}

/// `generic_asn1`: the DER of the value `ASN1_generate_v3` makes of `value`, or NULL.
///
/// # Safety
/// `value` is a C string; `ctx` is NULL or a live context.
unsafe fn generic_asn1(value: *const c_char, ctx: *mut X509V3_CTX, len: &mut c_long) -> *mut u8 {
    // SAFETY: the caller's guarantee.
    let typ = unsafe { crate::asn1::generate::ASN1_generate_v3(value, ctx) };
    if typ.is_null() {
        return ptr::null_mut();
    }
    let mut der = ptr::null_mut();
    // SAFETY: the value; a new buffer.
    *len = c_long::from(unsafe { crate::asn1::tpl::items::i2d_ASN1_TYPE(typ, &raw mut der) });
    // SAFETY: made above.
    unsafe { crate::asn1::tpl::items::ASN1_TYPE_free(typ) };
    der
}

/// `v3_generic_extension`: an extension of the object `ext` (a name or dotted) whose value
/// is the text's octets, or NULL.
///
/// # Safety
/// `ext` and `value` are C strings.
unsafe fn generic_extension(
    ext: *const c_char,
    value: *const c_char,
    crit: c_int,
    kind: c_int,
    ctx: *mut X509V3_CTX,
) -> *mut X509_EXTENSION {
    const F: &str = "v3_generic_extension";
    // SAFETY: the caller's guarantee.
    let obj = unsafe { OBJ_txt2obj(ext, 0) };
    if obj.is_null() {
        // SAFETY: as above.
        let d = data(&[("name", unsafe { text(ext) })], ", ");
        err::raise_with_bytes(ERR_LIB_X509V3, X509V3_R_EXTENSION_NAME_ERROR, F, &d);
        return ptr::null_mut();
    }
    let mut len: c_long = 0;
    let der = if kind == 1 {
        // SAFETY: as above; a place for the length.
        unsafe { OPENSSL_hexstr2buf(value, &raw mut len) }
    } else {
        // SAFETY: as above; the caller's context.
        unsafe { generic_asn1(value, ctx, &mut len) }
    };
    let mut extension = ptr::null_mut();
    if der.is_null() {
        // SAFETY: as above.
        let d = data(&[("value", unsafe { text(value) })], ", ");
        err::raise_with_bytes(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR, F, &d);
    } else {
        // SAFETY: no preconditions.
        let oct = unsafe { ASN1_OCTET_STRING_new() };
        // SAFETY: the new string, or NULL.
        match unsafe { oct.as_mut() } {
            None => {
                err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                // SAFETY: made above.
                unsafe { mem::release(der.cast()) };
            }
            Some(o) => {
                o.data = der;
                o.length = c_int::try_from(len).unwrap_or(0);
                // SAFETY: the object and string, copied into the extension.
                extension =
                    unsafe { X509_EXTENSION_create_by_OBJ(ptr::null_mut(), obj, crit, oct) };
            }
        }
        // SAFETY: made above, or NULL.
        unsafe { ASN1_OCTET_STRING_free(oct) };
    }
    // SAFETY: made above.
    unsafe { ASN1_OBJECT_free(obj) };
    extension
}

/// `do_ext_nconf`: an extension of `ext_nid` from the value through its method, or NULL.
///
/// # Safety
/// `conf` is NULL or a live configuration; `ctx` is a live context; `value` is a C string.
unsafe fn do_ext_nconf(
    conf: *mut CONF,
    ctx: *mut X509V3_CTX,
    ext_nid: c_int,
    crit: c_int,
    value: *const c_char,
) -> *mut X509_EXTENSION {
    const F: &str = "do_ext_nconf";
    if ext_nid == NID_undef {
        err::raise(ERR_LIB_X509V3, X509V3_R_UNKNOWN_EXTENSION_NAME, F);
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    let method = unsafe { X509V3_EXT_get_nid(ext_nid) };
    // SAFETY: a live method, or NULL.
    let Some(m) = (unsafe { method.as_ref() }) else {
        err::raise(ERR_LIB_X509V3, X509V3_R_UNKNOWN_EXTENSION, F);
        return ptr::null_mut();
    };
    // SAFETY: no preconditions.
    let sn = unsafe { OBJ_nid2sn(ext_nid) };
    // SAFETY: the NID's static short name, or NULL.
    let sn = unsafe { text(sn) };
    // SAFETY: the caller's guarantee.
    let v = unsafe { text(value) }.unwrap_or_default();
    let ext_struc = if let Some(v2i) = m.v2i {
        let from_section = v.first() == Some(&b'@');
        let nval = if from_section {
            // SAFETY: the value starts `@`, so a C string follows it.
            let section = unsafe { value.add(1) };
            // SAFETY: the caller's configuration; the section's name.
            unsafe { NCONF_get_section(conf, section) }
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { X509V3_parse_list(value) }
        };
        let free = |nval: *mut stack_st_CONF_VALUE| {
            if !from_section {
                // SAFETY: the parsed list, with its values.
                unsafe { OPENSSL_sk_pop_free(nval.cast(), Some(free_conf)) };
            }
        };
        // SAFETY: the list, or NULL.
        if nval.is_null() || unsafe { OPENSSL_sk_num(nval.cast()) } <= 0 {
            let d = data(&[("name", sn), ("section", Some(v))], ",");
            err::raise_with_bytes(ERR_LIB_X509V3, X509V3_R_INVALID_EXTENSION_STRING, F, &d);
            free(nval);
            return ptr::null_mut();
        }
        // SAFETY: the method's function, given the context and the list.
        let s = unsafe { v2i(method, ctx, nval) };
        free(nval);
        s
    } else if let Some(s2i) = m.s2i {
        // SAFETY: as above; the value.
        unsafe { s2i(method, ctx, value) }
    } else if let Some(r2i) = m.r2i {
        // SAFETY: the caller's context.
        let c = unsafe { &*ctx };
        if c.db.is_null() || c.db_meth.is_null() {
            err::raise(ERR_LIB_X509V3, X509V3_R_NO_CONFIG_DATABASE, F);
            return ptr::null_mut();
        }
        // SAFETY: as above; the value.
        unsafe { r2i(method, ctx, value) }
    } else {
        let d = data(&[("name", sn)], ",");
        err::raise_with_bytes(
            ERR_LIB_X509V3,
            X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED,
            F,
            &d,
        );
        return ptr::null_mut();
    };
    if ext_struc.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the method; a value of it.
    let ext = unsafe { do_ext_i2d(m, ext_nid, crit, ext_struc) };
    if let Some(it) = m.it {
        // SAFETY: the method's item.
        let it = unsafe { it() };
        // SAFETY: the value, of the method's item.
        unsafe { ASN1_item_free(ext_struc.cast(), it) };
    } else if let Some(free) = m.ext_free {
        // SAFETY: the value, the method's.
        unsafe { free(ext_struc) };
    }
    ext
}

/// `X509V3_conf_free` as a stack's free function.
unsafe extern "C" fn free_conf(c: *mut c_void) {
    // SAFETY: a `CONF_VALUE` of the stack, which the stack owned.
    unsafe { X509V3_conf_free(c.cast()) };
}

/// A context for `conf` alone, as OpenSSL makes when given none.
fn temporary_ctx(conf: *mut CONF) -> X509V3_CTX {
    // SAFETY: all-zero is a valid context (NULL pointers, no flags).
    let mut tmp: X509V3_CTX = unsafe { core::mem::zeroed() };
    // SAFETY: a live context.
    unsafe {
        X509V3_set_ctx(
            &raw mut tmp,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
        )
    };
    // SAFETY: as above; the configuration, or NULL.
    unsafe { X509V3_set_nconf(&raw mut tmp, conf) };
    tmp
}

/// `X509V3_EXT_nconf_int`.
///
/// # Safety
/// `conf` is NULL or a live configuration; `ctx` is a live context; the strings are NULL or
/// C strings.
unsafe fn nconf_int(
    conf: *mut CONF,
    ctx: *mut X509V3_CTX,
    section: *const c_char,
    name: *const c_char,
    value: *const c_char,
) -> *mut X509_EXTENSION {
    const F: &str = "X509V3_EXT_nconf_int";
    if name.is_null() || value.is_null() {
        err::raise(ERR_LIB_X509V3, ERR_R_PASSED_NULL_PARAMETER, F);
        return ptr::null_mut();
    }
    let mut value = value;
    // SAFETY: a C string.
    let crit = unsafe { check_critical(&mut value) };
    // SAFETY: as above.
    let kind = unsafe { check_generic(&mut value) };
    if kind != 0 {
        // SAFETY: C strings.
        return unsafe { generic_extension(name, value, crit, kind, ctx) };
    }
    // SAFETY: a C string.
    let nid = unsafe { OBJ_sn2nid(name) };
    // SAFETY: the caller's guarantee; a C string.
    let ret = unsafe { do_ext_nconf(conf, ctx, nid, crit, value) };
    if ret.is_null() {
        // SAFETY: C strings, or NULL.
        let (s, n, v) = (unsafe { text(section) }, unsafe { text(name) }, unsafe {
            text(value)
        });
        let d = if section.is_null() {
            data(&[("name", n), ("value", v)], ", ")
        } else {
            data(&[("section", s), ("name", n), ("value", v)], ", ")
        };
        err::raise_with_bytes(ERR_LIB_X509V3, X509V3_R_ERROR_IN_EXTENSION, F, &d);
    }
    ret
}

ffi_export! {
    /// The extension named `name` (a short name, or any object for a `DER:` value) made from
    /// `value`, its sections from `conf`, or NULL.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `ctx` is NULL or a live context; `name` and
    /// `value` are C strings (NULL fails, where OpenSSL crashes: docs/DEVIATIONS.md).
    pub unsafe extern "C" fn X509V3_EXT_nconf(conf: *mut CONF, ctx: *mut X509V3_CTX, name: *const c_char, value: *const c_char) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        let mut tmp = temporary_ctx(conf);
        let c = if ctx.is_null() { &raw mut tmp } else { ctx };
        // SAFETY: the caller's guarantee; a live context.
        unsafe { nconf_int(conf, c, ptr::null(), name, value) }
    }
}

ffi_export! {
    /// The extension of `ext_nid` made from `value`, or NULL.
    ///
    /// # Safety
    /// As for [`X509V3_EXT_nconf`].
    pub unsafe extern "C" fn X509V3_EXT_nconf_nid(conf: *mut CONF, ctx: *mut X509V3_CTX, ext_nid: c_int, value: *const c_char) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        if value.is_null() {
            err::raise(ERR_LIB_X509V3, ERR_R_PASSED_NULL_PARAMETER, "X509V3_EXT_nconf_nid");
            return ptr::null_mut();
        }
        let mut tmp = temporary_ctx(conf);
        let c = if ctx.is_null() { &raw mut tmp } else { ctx };
        let mut value = value;
        // SAFETY: a C string.
        let crit = unsafe { check_critical(&mut value) };
        // SAFETY: as above.
        let kind = unsafe { check_generic(&mut value) };
        if kind != 0 {
            // SAFETY: no preconditions.
            let sn = unsafe { OBJ_nid2sn(ext_nid) };
            if sn.is_null() {
                let d = data(&[("name", None)], ", ");
                err::raise_with_bytes(ERR_LIB_X509V3, X509V3_R_EXTENSION_NAME_ERROR, "v3_generic_extension", &d);
                return ptr::null_mut();
            }
            // SAFETY: C strings.
            return unsafe { generic_extension(sn, value, crit, kind, c) };
        }
        // SAFETY: the caller's guarantee; a live context.
        unsafe { do_ext_nconf(conf, c, ext_nid, crit, value) }
    }
}

/// Runs `f` with a temporary `CONF` over the legacy hash `conf`, as OpenSSL's `CONF`
/// functions do.
fn with_lhash<T>(conf: *mut lhash_st_CONF_VALUE, fail: T, f: impl FnOnce(*mut CONF) -> T) -> T {
    // SAFETY: no preconditions.
    let ctmp = unsafe { NCONF_new(ptr::null_mut()) };
    if ctmp.is_null() {
        return fail;
    }
    // SAFETY: the new configuration; the caller's hash, or NULL.
    unsafe { CONF_set_nconf(ctmp, conf) };
    let r = f(ctmp);
    // SAFETY: as above.
    unsafe { CONF_set_nconf(ctmp, ptr::null_mut()) };
    // SAFETY: made above, without the caller's hash.
    unsafe { NCONF_free(ctmp) };
    r
}

ffi_export! {
    /// [`X509V3_EXT_nconf`] over a legacy `CONF` hash.
    ///
    /// # Safety
    /// `conf` is NULL or a live hash; otherwise as for [`X509V3_EXT_nconf`].
    pub unsafe extern "C" fn X509V3_EXT_conf(conf: *mut lhash_st_CONF_VALUE, ctx: *mut X509V3_CTX, name: *const c_char, value: *const c_char) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        with_lhash(conf, ptr::null_mut(), |c| unsafe { X509V3_EXT_nconf(c, ctx, name, value) })
    }
}

ffi_export! {
    /// [`X509V3_EXT_nconf_nid`] over a legacy `CONF` hash.
    ///
    /// # Safety
    /// As for [`X509V3_EXT_conf`].
    pub unsafe extern "C" fn X509V3_EXT_conf_nid(conf: *mut lhash_st_CONF_VALUE, ctx: *mut X509V3_CTX, ext_nid: c_int, value: *const c_char) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        with_lhash(conf, ptr::null_mut(), |c| unsafe { X509V3_EXT_nconf_nid(c, ctx, ext_nid, value) })
    }
}

/// `delete_ext`: removes the extensions of `ext`'s type from the list.
///
/// # Safety
/// `sk` is NULL or a live list; `ext` is a live extension.
unsafe fn delete_ext(sk: *mut stack_st_X509_EXTENSION, ext: *mut X509_EXTENSION) {
    // SAFETY: the caller's guarantee.
    let obj = unsafe { X509_EXTENSION_get_object(ext) };
    loop {
        // SAFETY: as above.
        let idx = unsafe { X509v3_get_ext_by_OBJ(sk, obj, -1) };
        if idx < 0 {
            return;
        }
        // SAFETY: as above; an index within it.
        let e = unsafe { X509v3_delete_ext(sk, idx) };
        // SAFETY: removed from the list, now ours.
        unsafe { X509_EXTENSION_free(e) };
    }
}

ffi_export! {
    /// Makes each extension of the configuration's `section` and adds it to `*sk` (if `sk`
    /// isn't NULL): 1, or 0 at the first that fails.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `ctx` is NULL or a live context; `section` is
    /// NULL or a C string; `sk` is NULL or holds NULL or a live list.
    pub unsafe extern "C" fn X509V3_EXT_add_nconf_sk(conf: *mut CONF, ctx: *mut X509V3_CTX, section: *const c_char, sk: *mut *mut stack_st_X509_EXTENSION) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        let mut tmp = temporary_ctx(conf);
        let ctx = if ctx.is_null() { &raw mut tmp } else { ctx };
        // SAFETY: the caller's guarantee.
        let nval = unsafe { NCONF_get_section(conf, section) };
        if nval.is_null() {
            return 0;
        }
        let value = |i: c_int| {
            // SAFETY: an index within the section.
            unsafe { OPENSSL_sk_value(nval.cast(), i) }.cast::<CONF_VALUE>()
        };
        let name_of = |i: c_int| {
            // SAFETY: a value of the section, or NULL.
            unsafe { value(i).as_ref() }.and_then(|v| unsafe { text(v.name) })
        };
        // SAFETY: the section.
        let n = unsafe { OPENSSL_sk_num(nval.cast()) };
        let (mut akid, mut skid) = (-1, -1);
        for i in 0..n {
            match name_of(i) {
                Some(b"authorityKeyIdentifier") => akid = i,
                Some(b"subjectKeyIdentifier") => skid = i,
                _ => {}
            }
        }
        for i in 0..n {
            let mut j = i;
            if skid > akid && akid >= 0 {
                if i == akid {
                    j = skid;
                } else if i == skid {
                    j = akid;
                }
            }
            // SAFETY: a value of the section, or NULL.
            let Some(val) = (unsafe { value(j).as_ref() }) else { return 0 };
            // SAFETY: the caller's guarantee; the value's strings.
            let ext = unsafe { nconf_int(conf, ctx, val.section, val.name, val.value) };
            if ext.is_null() {
                return 0;
            }
            if !sk.is_null() {
                // SAFETY: the context.
                if unsafe { (*ctx).flags } == X509V3_CTX_REPLACE {
                    // SAFETY: the caller's list slot.
                    let list = unsafe { sk.read() };
                    // SAFETY: the list, or NULL; the extension.
                    unsafe { delete_ext(list, ext) };
                }
                // SAFETY: the caller's list slot; the extension, copied.
                if unsafe { X509v3_add_ext(sk, ext, -1) }.is_null() {
                    // SAFETY: made above.
                    unsafe { X509_EXTENSION_free(ext) };
                    return 0;
                }
            }
            // SAFETY: as above.
            unsafe { X509_EXTENSION_free(ext) };
        }
        1
    }
}

ffi_export! {
    /// Adds the section's extensions to the certificate (or only makes them, for NULL): 1,
    /// or 0.
    ///
    /// # Safety
    /// As for [`X509V3_EXT_add_nconf_sk`]; `cert` is NULL or a live certificate.
    pub unsafe extern "C" fn X509V3_EXT_add_nconf(conf: *mut CONF, ctx: *mut X509V3_CTX, section: *const c_char, cert: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let sk = unsafe { cert_of(cert) }.map_or(ptr::null_mut(), |c| &raw mut c.cert_info.extensions);
        // SAFETY: as above; the certificate's list, or NULL.
        unsafe { X509V3_EXT_add_nconf_sk(conf, ctx, section, sk) }
    }
}

ffi_export! {
    /// Adds the section's extensions to the request (as its extension request attribute): 1,
    /// or 0.
    ///
    /// # Safety
    /// As for [`X509V3_EXT_add_nconf_sk`]; `req` is NULL or a live request.
    pub unsafe extern "C" fn X509V3_EXT_REQ_add_nconf(conf: *mut CONF, ctx: *mut X509V3_CTX, section: *const c_char, req: *mut X509_REQ) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        let mut exts: *mut stack_st_X509_EXTENSION = ptr::null_mut();
        // SAFETY: the caller's guarantee; a local list.
        let mut ret = unsafe { X509V3_EXT_add_nconf_sk(conf, ctx, section, &raw mut exts) };
        if ret != 0 && !req.is_null() && !exts.is_null() {
            // SAFETY: the caller's request; the list.
            ret = unsafe { X509_REQ_add_extensions(req, exts) };
        }
        // SAFETY: made here, or NULL, with its extensions.
        unsafe { OPENSSL_sk_pop_free(exts.cast(), Some(crate::x509v3::registry::free_ext)) };
        ret
    }
}

ffi_export! {
    /// [`X509V3_EXT_add_nconf`] over a legacy `CONF` hash.
    ///
    /// # Safety
    /// `conf` is NULL or a live hash; otherwise as for [`X509V3_EXT_add_nconf`].
    pub unsafe extern "C" fn X509V3_EXT_add_conf(conf: *mut lhash_st_CONF_VALUE, ctx: *mut X509V3_CTX, section: *const c_char, cert: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        with_lhash(conf, 0, |c| unsafe { X509V3_EXT_add_nconf(c, ctx, section, cert) })
    }
}

ffi_export! {
    /// [`X509V3_EXT_REQ_add_nconf`] over a legacy `CONF` hash.
    ///
    /// # Safety
    /// `conf` is NULL or a live hash; otherwise as for [`X509V3_EXT_REQ_add_nconf`].
    pub unsafe extern "C" fn X509V3_EXT_REQ_add_conf(conf: *mut lhash_st_CONF_VALUE, ctx: *mut X509V3_CTX, section: *const c_char, req: *mut X509_REQ) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        with_lhash(conf, 0, |c| unsafe { X509V3_EXT_REQ_add_nconf(c, ctx, section, req) })
    }
}

ffi_export! {
    /// Adds the section's extensions to the CRL (or only makes them, for NULL): 1, or 0.
    ///
    /// # Safety
    /// As for [`X509V3_EXT_add_nconf_sk`]; `crl` is NULL or a live CRL.
    pub unsafe extern "C" fn X509V3_EXT_CRL_add_nconf(conf: *mut CONF, ctx: *mut X509V3_CTX, section: *const c_char, crl: *mut X509_CRL) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let sk = unsafe { crate::x509::crl::crl_of(crl) }.map_or(ptr::null_mut(), |c| &raw mut c.crl.extensions);
        // SAFETY: as above; the CRL's list, or NULL.
        unsafe { X509V3_EXT_add_nconf_sk(conf, ctx, section, sk) }
    }
}

ffi_export! {
    /// [`X509V3_EXT_CRL_add_nconf`] over a legacy `CONF` hash.
    ///
    /// # Safety
    /// `conf` is NULL or a live hash; otherwise as for [`X509V3_EXT_CRL_add_nconf`].
    pub unsafe extern "C" fn X509V3_EXT_CRL_add_conf(conf: *mut lhash_st_CONF_VALUE, ctx: *mut X509V3_CTX, section: *const c_char, crl: *mut X509_CRL) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        with_lhash(conf, 0, |c| unsafe { X509V3_EXT_CRL_add_nconf(c, ctx, section, crl) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: a NULL name or value, which OpenSSL reads through, fails.
    #[test]
    fn null_names_and_values_fail() {
        // SAFETY: NULL where OpenSSL dereferences it.
        let e = unsafe {
            X509V3_EXT_nconf(ptr::null_mut(), ptr::null_mut(), ptr::null(), c"x".as_ptr())
        };
        assert!(e.is_null());
        // SAFETY: as above.
        let e = unsafe {
            X509V3_EXT_nconf(
                ptr::null_mut(),
                ptr::null_mut(),
                c"keyUsage".as_ptr(),
                ptr::null(),
            )
        };
        assert!(e.is_null());
        // SAFETY: as above.
        let e = unsafe {
            X509V3_EXT_nconf_nid(
                ptr::null_mut(),
                ptr::null_mut(),
                rustyssl_abi::NID_key_usage,
                ptr::null(),
            )
        };
        assert!(e.is_null());
        crate::err::take_all();
    }
}
