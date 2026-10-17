//! The extension context (`X509V3_set_ctx(3)`; the context parts of `v3_conf.c`, and
//! `X509V3_NAME_from_section` of `v3_utl.c`): the certificates, request, CRL, and issuer key
//! an extension is made for, and the configuration its sections come from (an `NCONF` or a
//! legacy `CONF` hash), through the context's `X509V3_CONF_METHOD`.

use core::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    CONF, CONF_VALUE, ERR_LIB_X509V3, ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_PASSED_NULL_PARAMETER,
    EVP_PKEY, X509, X509_CRL, X509_NAME, X509_REQ, X509V3_CONF_METHOD, X509V3_CTX,
    X509V3_R_OPERATION_NOT_DEFINED, lhash_st_CONF_VALUE, stack_st_CONF_VALUE,
};

use crate::conf::{CONF_get_section, CONF_get_string, NCONF_get_section, NCONF_get_string};
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::name::X509_NAME_add_entry_by_txt;

/// A method table in a static.
struct ConfMethod(X509V3_CONF_METHOD);

// SAFETY: immutable, with only function pointers.
unsafe impl Sync for ConfMethod {}

ffi_callback! {
    /// `nconf_get_string`.
    ///
    /// # Safety
    /// `db` is a live `CONF`; the names are NULL or C strings.
    pub(crate) unsafe extern "C" fn nconf_get_string(db: *mut c_void, section: *const c_char, value: *const c_char) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { NCONF_get_string(db.cast(), section, value) }
    }
}

ffi_callback! {
    /// `nconf_get_section`.
    ///
    /// # Safety
    /// `db` is a live `CONF`; `section` is NULL or a C string.
    pub(crate) unsafe extern "C" fn nconf_get_section(db: *mut c_void, section: *const c_char) -> *mut stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { NCONF_get_section(db.cast(), section) }
    }
}

static NCONF_METHOD: ConfMethod = ConfMethod(X509V3_CONF_METHOD {
    get_string: Some(nconf_get_string),
    get_section: Some(nconf_get_section),
    free_string: None,
    free_section: None,
});

ffi_callback! {
    /// `conf_lhash_get_string`.
    ///
    /// # Safety
    /// `db` is a live legacy `CONF` hash; the names are NULL or C strings.
    pub(crate) unsafe extern "C" fn lhash_get_string(db: *mut c_void, section: *const c_char, value: *const c_char) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { CONF_get_string(db.cast(), section, value) }
    }
}

ffi_callback! {
    /// `conf_lhash_get_section`.
    ///
    /// # Safety
    /// `db` is a live legacy `CONF` hash; `section` is NULL or a C string.
    pub(crate) unsafe extern "C" fn lhash_get_section(db: *mut c_void, section: *const c_char) -> *mut stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { CONF_get_section(db.cast(), section) }
    }
}

static LHASH_METHOD: ConfMethod = ConfMethod(X509V3_CONF_METHOD {
    get_string: Some(lhash_get_string),
    get_section: Some(lhash_get_section),
    free_string: None,
    free_section: None,
});

ffi_export! {
    /// Sets the context's certificates, request, CRL, and flags, with no configuration and no
    /// issuer key.
    ///
    /// # Safety
    /// `ctx` is NULL or writable; the others are NULL or live objects that outlive its use.
    pub unsafe extern "C" fn X509V3_set_ctx(ctx: *mut X509V3_CTX, issuer: *mut X509, subj: *mut X509, req: *mut X509_REQ, crl: *mut X509_CRL, flags: c_int)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx.as_mut() }) else {
            err::raise(ERR_LIB_X509V3, ERR_R_PASSED_NULL_PARAMETER, "X509V3_set_ctx");
            return;
        };
        c.flags = flags;
        c.issuer_cert = issuer;
        c.subject_cert = subj;
        c.subject_req = req;
        c.crl = crl;
        c.db_meth = ptr::null_mut();
        c.db = ptr::null_mut();
        c.issuer_pkey = ptr::null_mut();
    }
}

ffi_export! {
    /// Gives the context the issuer's private key (refused without a subject certificate):
    /// 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `pkey` is NULL or a key that outlives its use.
    pub unsafe extern "C" fn X509V3_set_issuer_pkey(ctx: *mut X509V3_CTX, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        const F: &str = "X509V3_set_issuer_pkey";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx.as_mut() }) else {
            err::raise(ERR_LIB_X509V3, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        };
        if c.subject_cert.is_null() && !pkey.is_null() {
            err::raise(ERR_LIB_X509V3, ERR_R_PASSED_INVALID_ARGUMENT, F);
            return 0;
        }
        c.issuer_pkey = pkey;
        1
    }
}

ffi_export! {
    /// The context's sections come from `conf` (`NCONF_get_section`).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `conf` is NULL or a `CONF` that outlives its use.
    pub unsafe extern "C" fn X509V3_set_nconf(ctx: *mut X509V3_CTX, conf: *mut CONF)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx.as_mut() }) else {
            err::raise(ERR_LIB_X509V3, ERR_R_PASSED_NULL_PARAMETER, "X509V3_set_nconf");
            return;
        };
        c.db_meth = (&raw const NCONF_METHOD.0).cast_mut();
        c.db = conf.cast();
    }
}

ffi_export! {
    /// The context's sections come from a legacy `CONF` hash (`CONF_get_section`).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `lhash` is NULL or a hash that outlives its use.
    pub unsafe extern "C" fn X509V3_set_conf_lhash(ctx: *mut X509V3_CTX, lhash: *mut lhash_st_CONF_VALUE)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx.as_mut() }) else {
            err::raise(ERR_LIB_X509V3, ERR_R_PASSED_NULL_PARAMETER, "X509V3_set_conf_lhash");
            return;
        };
        c.db_meth = (&raw const LHASH_METHOD.0).cast_mut();
        c.db = lhash.cast();
    }
}

/// The context's configuration method, if it has a configuration.
///
/// # Safety
/// `ctx` is NULL or a live context.
unsafe fn conf_method<'a>(ctx: *mut X509V3_CTX) -> Option<(&'a X509V3_CONF_METHOD, *mut c_void)> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { ctx.as_ref() }?;
    if c.db.is_null() {
        return None;
    }
    // SAFETY: the context's method, which outlives it.
    unsafe { c.db_meth.as_ref() }.map(|m| (m, c.db))
}

ffi_export! {
    /// The value `name` of `section` in the context's configuration, or NULL
    /// (`X509V3_R_OPERATION_NOT_DEFINED` without one).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; the names are NULL or C strings.
    pub unsafe extern "C" fn X509V3_get_string(ctx: *mut X509V3_CTX, name: *const c_char, section: *const c_char) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let f = unsafe { conf_method(ctx) }.and_then(|(m, db)| m.get_string.map(|f| (f, db)));
        let Some((f, db)) = f else {
            err::raise(ERR_LIB_X509V3, X509V3_R_OPERATION_NOT_DEFINED, "X509V3_get_string");
            return ptr::null_mut();
        };
        // SAFETY: the method's function, given its configuration.
        unsafe { f(db, name, section) }
    }
}

ffi_export! {
    /// The values of `section` in the context's configuration, or NULL
    /// (`X509V3_R_OPERATION_NOT_DEFINED` without one).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `section` is NULL or a C string.
    pub unsafe extern "C" fn X509V3_get_section(ctx: *mut X509V3_CTX, section: *const c_char) -> *mut stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let f = unsafe { conf_method(ctx) }.and_then(|(m, db)| m.get_section.map(|f| (f, db)));
        let Some((f, db)) = f else {
            err::raise(ERR_LIB_X509V3, X509V3_R_OPERATION_NOT_DEFINED, "X509V3_get_section");
            return ptr::null_mut();
        };
        // SAFETY: the method's function, given its configuration.
        unsafe { f(db, section) }
    }
}

ffi_export! {
    /// Frees a string `X509V3_get_string` returned, through the context's method (whose
    /// strings are usually the configuration's own: nothing to free).
    ///
    /// # Safety
    /// `ctx` is a live context with a method; `str` is NULL or a string of it.
    pub unsafe extern "C" fn X509V3_string_free(ctx: *mut X509V3_CTX, str: *mut c_char)
    where failure = (), library = ERR_LIB_X509V3
    {
        if str.is_null() {
            return;
        }
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx.as_ref() }
            // SAFETY: as above.
            && let Some(m) = unsafe { c.db_meth.as_ref() }
            && let Some(f) = m.free_string
        {
            // SAFETY: the method's function, given its configuration and string.
            unsafe { f(c.db, str) };
        }
    }
}

ffi_export! {
    /// Frees a section `X509V3_get_section` returned, through the context's method.
    ///
    /// # Safety
    /// `ctx` is a live context with a method; `section` is NULL or a section of it.
    pub unsafe extern "C" fn X509V3_section_free(ctx: *mut X509V3_CTX, section: *mut stack_st_CONF_VALUE)
    where failure = (), library = ERR_LIB_X509V3
    {
        if section.is_null() {
            return;
        }
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx.as_ref() }
            // SAFETY: as above.
            && let Some(m) = unsafe { c.db_meth.as_ref() }
            && let Some(f) = m.free_section
        {
            // SAFETY: the method's function, given its configuration and section.
            unsafe { f(c.db, section) };
        }
    }
}

ffi_export! {
    /// Adds an entry to `nm` for each value of `dn_sk`: the field is the value's name after
    /// its first `:`, `,`, or `.` (if anything follows), a leading `+` joining the previous
    /// RDN. 1, or 0.
    ///
    /// # Safety
    /// `nm` is NULL or a live name; `dn_sk` is NULL or a live stack of `CONF_VALUE`s.
    pub unsafe extern "C" fn X509V3_NAME_from_section(nm: *mut X509_NAME, dn_sk: *mut stack_st_CONF_VALUE, chtype: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        if nm.is_null() {
            return 0;
        }
        let Ok(chtype) = c_int::try_from(chtype) else { return 0 };
        // SAFETY: the caller's stack, or NULL.
        let n = unsafe { OPENSSL_sk_num(dn_sk.cast()) };
        for i in 0..n {
            // SAFETY: an index within the stack; a `CONF_VALUE`.
            let v = unsafe { OPENSSL_sk_value(dn_sk.cast(), i) }.cast::<CONF_VALUE>();
            // SAFETY: as above.
            let Some(v) = (unsafe { v.as_ref() }) else { continue };
            if v.name.is_null() {
                return 0;
            }
            // SAFETY: its name, a C string.
            let name = unsafe { CStr::from_ptr(v.name) }.to_bytes();
            let mut start = 0usize;
            if let Some(p) = name.iter().position(|&c| c == b':' || c == b',' || c == b'.') {
                let next = p.saturating_add(1);
                if next < name.len() {
                    start = next;
                }
            }
            let (mval, start) = if name.get(start) == Some(&b'+') { (-1, start.saturating_add(1)) } else { (0, start) };
            let field = v.name.wrapping_add(start);
            // SAFETY: the caller's name; the field's name within the value's; its value.
            if unsafe { X509_NAME_add_entry_by_txt(nm, field, chtype, v.value.cast(), -1, -1, mval) } == 0 {
                return 0;
            }
        }
        1
    }
}
