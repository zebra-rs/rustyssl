//! Configuring a TSA (`ts_conf.c`): loading its certificates and key, and setting a response
//! context from a configuration's TSA section, as `openssl ts -reply` does.

use core::ffi::{CStr, c_char, c_int, c_long, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    CONF, CONF_VALUE, ERR_LIB_TS, EVP_MD, EVP_PKEY, TS_ESS_CERT_ID_CHAIN,
    TS_MAX_CLOCK_PRECISION_DIGITS, TS_ORDERING, TS_R_CANNOT_LOAD_CERT, TS_R_CANNOT_LOAD_KEY,
    TS_R_COULD_NOT_SET_ENGINE, TS_R_VAR_BAD_VALUE, TS_R_VAR_LOOKUP_FAILURE, TS_RESP_CTX,
    TS_TSA_NAME, TS_serial_cb, X509, X509_ADD_FLAG_DEFAULT, X509_INFO, stack_st_CONF_VALUE,
    stack_st_X509,
};

use super::sign::{
    TS_RESP_CTX_add_flags, TS_RESP_CTX_add_md, TS_RESP_CTX_add_policy, TS_RESP_CTX_set_accuracy,
    TS_RESP_CTX_set_certs, TS_RESP_CTX_set_clock_precision_digits, TS_RESP_CTX_set_def_policy,
    TS_RESP_CTX_set_ess_cert_id_digest, TS_RESP_CTX_set_serial_cb, TS_RESP_CTX_set_signer_cert,
    TS_RESP_CTX_set_signer_digest, TS_RESP_CTX_set_signer_key,
};
use crate::bio::BIO_free;
use crate::bio::file::BIO_new_file;
use crate::conf::{NCONF_get_number_e, NCONF_get_string};
use crate::ec_pmeth::atoi;
use crate::err::{self, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::legacy_md::EVP_get_digestbyname;
use crate::evp::pkey::EVP_PKEY_free;
use crate::ffi::ffi_export;
use crate::objects::{ASN1_OBJECT_free, OBJ_txt2obj};
use crate::pem_pkey::{PEM_read_bio_PrivateKey, PEM_read_bio_X509_AUX};
use crate::stack::{OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value};
use crate::x509::cert::{OSSL_STACK_OF_X509_free, X509_free};
use crate::x509::info::{PEM_X509_INFO_read_bio, X509_INFO_free};
use crate::x509::purpose::X509_add_cert;
use crate::x509v3::{X509V3_conf_free, X509V3_parse_list};

const BASE_SECTION: &CStr = c"tsa";

/// The C string as `%s` prints it.
///
/// # Safety
/// `p` is NULL or a C string.
unsafe fn text(p: *const c_char) -> Vec<u8> {
    if p.is_null() {
        return b"(null)".to_vec();
    }
    // SAFETY: the caller's string.
    unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
}

/// `section::tag`, as the error's data.
///
/// # Safety
/// `section` is NULL or a C string.
unsafe fn raise_var(reason: c_int, f: &str, section: *const c_char, tag: &CStr) {
    // SAFETY: the caller's string.
    let mut d = unsafe { text(section) };
    d.extend_from_slice(b"::");
    d.extend_from_slice(tag.to_bytes());
    err::raise_with_bytes(ERR_LIB_TS, reason, f, &d);
}

/// `ts_CONF_lookup_fail`.
///
/// # Safety
/// `section` is NULL or a C string.
unsafe fn lookup_fail(section: *const c_char, tag: &CStr) {
    // SAFETY: the caller's string.
    unsafe { raise_var(TS_R_VAR_LOOKUP_FAILURE, "ts_CONF_lookup_fail", section, tag) };
}

/// `ts_CONF_invalid`.
///
/// # Safety
/// `section` is NULL or a C string.
unsafe fn invalid(section: *const c_char, tag: &CStr) {
    // SAFETY: the caller's string.
    unsafe { raise_var(TS_R_VAR_BAD_VALUE, "ts_CONF_invalid", section, tag) };
}

/// The configuration's value `name` in `section`, or NULL.
///
/// # Safety
/// `conf` is NULL or a live configuration; `section` NULL or a C string.
unsafe fn get(conf: *const CONF, section: *const c_char, name: &CStr) -> *mut c_char {
    // SAFETY: the caller's guarantee.
    unsafe { NCONF_get_string(conf, section, name.as_ptr()) }
}

ffi_export! {
    /// The first certificate in the PEM file (trusted form accepted), or NULL.
    ///
    /// # Safety
    /// `file` is a C string.
    pub unsafe extern "C" fn TS_CONF_load_cert(file: *const c_char) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's name.
        let bio = unsafe { BIO_new_file(file, c"r".as_ptr()) };
        let x = if bio.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: the BIO opened here.
            unsafe { PEM_read_bio_X509_AUX(bio, ptr::null_mut(), None, ptr::null_mut()) }
        };
        if x.is_null() {
            err::raise(ERR_LIB_TS, TS_R_CANNOT_LOAD_CERT, "TS_CONF_load_cert");
        }
        // SAFETY: as above, or NULL.
        unsafe { BIO_free(bio) };
        x
    }
}

/// `X509_INFO_free` as a stack's free function.
unsafe extern "C" fn info_free(p: *mut c_void) {
    // SAFETY: an element of a list of infos.
    unsafe { X509_INFO_free(p.cast()) };
}

/// `X509V3_conf_free` as a stack's free function.
unsafe extern "C" fn conf_value_free(p: *mut c_void) {
    // SAFETY: an element of a list of values.
    unsafe { X509V3_conf_free(p.cast()) };
}

/// The certificates of the PEM infos read from `bio`, or NULL.
///
/// # Safety
/// `bio` is a live BIO.
unsafe fn certs_of(bio: *mut rustyssl_abi::BIO) -> *mut stack_st_X509 {
    // SAFETY: no requirements.
    let mut certs: *mut stack_st_X509 = unsafe { OPENSSL_sk_new_null() }.cast();
    if certs.is_null() {
        return certs;
    }
    // SAFETY: the caller's BIO.
    let all = unsafe { PEM_X509_INFO_read_bio(bio, ptr::null_mut(), None, ptr::null_mut()) };
    // SAFETY: the infos, or NULL (0).
    let n = unsafe { OPENSSL_sk_num(all.cast()) };
    for i in 0..n {
        // SAFETY: an index in range.
        let xi: *mut X509_INFO = unsafe { OPENSSL_sk_value(all.cast(), i) }.cast();
        // SAFETY: an info.
        let x = unsafe { (*xi).x509 };
        if !x.is_null() {
            // SAFETY: the list; the certificate, which it takes.
            if unsafe { X509_add_cert(certs, x, X509_ADD_FLAG_DEFAULT) } == 0 {
                // SAFETY: the list made here.
                unsafe { OSSL_STACK_OF_X509_free(certs) };
                certs = ptr::null_mut();
                break;
            }
            // SAFETY: as above; the list holds it now.
            unsafe { (*xi).x509 = ptr::null_mut() };
        }
    }
    // SAFETY: the infos read here, or NULL.
    unsafe { OPENSSL_sk_pop_free(all.cast(), Some(info_free)) };
    certs
}

ffi_export! {
    /// The certificates in the PEM file, or NULL.
    ///
    /// # Safety
    /// `file` is a C string.
    pub unsafe extern "C" fn TS_CONF_load_certs(file: *const c_char) -> *mut stack_st_X509
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's name.
        let bio = unsafe { BIO_new_file(file, c"r".as_ptr()) };
        let certs = if bio.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: the BIO opened here.
            unsafe { certs_of(bio) }
        };
        if certs.is_null() {
            err::raise(ERR_LIB_TS, TS_R_CANNOT_LOAD_CERT, "TS_CONF_load_certs");
        }
        // SAFETY: as above, or NULL.
        unsafe { BIO_free(bio) };
        certs
    }
}

ffi_export! {
    /// The private key in the PEM file, decrypted with `pass`, or NULL.
    ///
    /// # Safety
    /// `file` is a C string; `pass` NULL or a C string.
    pub unsafe extern "C" fn TS_CONF_load_key(file: *const c_char, pass: *const c_char) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's name.
        let bio = unsafe { BIO_new_file(file, c"r".as_ptr()) };
        let pkey = if bio.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: the BIO opened here; the caller's pass phrase, or NULL.
            unsafe { PEM_read_bio_PrivateKey(bio, ptr::null_mut(), None, pass.cast_mut().cast()) }
        };
        if pkey.is_null() {
            err::raise(ERR_LIB_TS, TS_R_CANNOT_LOAD_KEY, "TS_CONF_load_key");
        }
        // SAFETY: as above, or NULL.
        unsafe { BIO_free(bio) };
        pkey
    }
}

ffi_export! {
    /// `section`, or the configuration's default TSA section, or NULL.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `section` NULL or a C string.
    pub unsafe extern "C" fn TS_CONF_get_tsa_section(conf: *mut CONF, section: *const c_char) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_TS
    {
        if !section.is_null() {
            return section;
        }
        // SAFETY: the caller's configuration.
        let s = unsafe { get(conf, BASE_SECTION.as_ptr(), c"default_tsa") };
        if s.is_null() {
            // SAFETY: a C string.
            unsafe { lookup_fail(BASE_SECTION.as_ptr(), c"default_tsa") };
        }
        s
    }
}

ffi_export! {
    /// Sets the serial callback, with the section's `serial` file as its data: 1, or 0.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `section` NULL or a C string; `ctx` a live
    /// context; `cb` NULL or a callback taking the file name.
    pub unsafe extern "C" fn TS_CONF_set_serial(conf: *mut CONF, section: *const c_char, cb: TS_serial_cb, ctx: *mut TS_RESP_CTX) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let serial = unsafe { get(conf, section, c"serial") };
        if serial.is_null() {
            // SAFETY: as above.
            unsafe { lookup_fail(section, c"serial") };
            return 0;
        }
        // SAFETY: the caller's context; the configuration's string.
        unsafe { TS_RESP_CTX_set_serial_cb(ctx, cb, serial.cast()) };
        1
    }
}

ffi_export! {
    /// Makes the engine the default for everything: 1 (always for `builtin`), or 0.
    ///
    /// # Safety
    /// `name` is a C string.
    pub unsafe extern "C" fn TS_CONF_set_default_engine(name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's string.
        let n = unsafe { text(name) };
        if n == b"builtin" {
            return 1;
        }
        // SAFETY: as above.
        let e = unsafe { crate::engine::ENGINE_by_id(name) };
        if !e.is_null() {
            if n == b"chil" {
                // SAFETY: a live engine; OpenSSL's fork-check command for that engine.
                unsafe {
                    crate::engine::ENGINE_ctrl(e, rustyssl_abi::ENGINE_CTRL_CHIL_SET_FORKCHECK, 1, core::ptr::null_mut(), None)
                };
            }
            // SAFETY: as above.
            let ok = unsafe { crate::engine::ENGINE_set_default(e, rustyssl_abi::ENGINE_METHOD_ALL) } != 0;
            // SAFETY: our reference.
            unsafe { crate::engine::ENGINE_free(e) };
            if ok {
                return 1;
            }
        }
        let mut d = b"engine:".to_vec();
        d.extend_from_slice(&n);
        err::raise_with_bytes(ERR_LIB_TS, TS_R_COULD_NOT_SET_ENGINE, "TS_CONF_set_default_engine", &d);
        0
    }
}

ffi_export! {
    /// Sets the default engine to `device`, or the section's `crypto_device`, if any: 1, or 0.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `section` and `device` NULL or C strings.
    pub unsafe extern "C" fn TS_CONF_set_crypto_device(conf: *mut CONF, section: *const c_char, device: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        let device = if device.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { get(conf, section, c"crypto_device") }.cast_const()
        } else {
            device
        };
        // SAFETY: a C string.
        if !device.is_null() && unsafe { TS_CONF_set_default_engine(device) } == 0 {
            // SAFETY: as above.
            unsafe { invalid(section, c"crypto_device") };
            return 0;
        }
        1
    }
}

/// `value`, or the section's `tag`; NULL (with the error) when neither is set.
///
/// # Safety
/// `conf` is NULL or a live configuration; `section` and `value` NULL or C strings.
unsafe fn value_or(
    conf: *const CONF,
    section: *const c_char,
    value: *const c_char,
    tag: &CStr,
) -> *const c_char {
    if !value.is_null() {
        return value;
    }
    // SAFETY: the caller's guarantee.
    let v = unsafe { get(conf, section, tag) };
    if v.is_null() {
        // SAFETY: as above.
        unsafe { lookup_fail(section, tag) };
    }
    v
}

ffi_export! {
    /// Sets the signer's certificate from the file `cert` or the section's `signer_cert`:
    /// 1, or 0.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `section` and `cert` NULL or C strings; `ctx`
    /// a live context.
    pub unsafe extern "C" fn TS_CONF_set_signer_cert(conf: *mut CONF, section: *const c_char, cert: *const c_char, ctx: *mut TS_RESP_CTX) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let cert = unsafe { value_or(conf, section, cert, c"signer_cert") };
        if cert.is_null() {
            return 0;
        }
        // SAFETY: a C string.
        let x = unsafe { TS_CONF_load_cert(cert) };
        // SAFETY: the caller's context; the certificate.
        let ok = !x.is_null() && unsafe { TS_RESP_CTX_set_signer_cert(ctx, x) } != 0;
        // SAFETY: loaded here, or NULL.
        unsafe { X509_free(x) };
        c_int::from(ok)
    }
}

ffi_export! {
    /// Sets the certificates to include from the file `certs` or the section's `certs`, if
    /// any: 1, or 0.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `section` and `certs` NULL or C strings; `ctx`
    /// a live context.
    pub unsafe extern "C" fn TS_CONF_set_certs(conf: *mut CONF, section: *const c_char, certs: *const c_char, ctx: *mut TS_RESP_CTX) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        let certs = if certs.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { get(conf, section, c"certs") }.cast_const()
        } else {
            certs
        };
        if certs.is_null() {
            return 1;
        }
        // SAFETY: a C string.
        let list = unsafe { TS_CONF_load_certs(certs) };
        // SAFETY: the caller's context; the list.
        let ok = !list.is_null() && unsafe { TS_RESP_CTX_set_certs(ctx, list) } != 0;
        // SAFETY: loaded here, or NULL.
        unsafe { OSSL_STACK_OF_X509_free(list) };
        c_int::from(ok)
    }
}

ffi_export! {
    /// Sets the signer's key from the file `key` or the section's `signer_key`: 1, or 0.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `section`, `key`, and `pass` NULL or C
    /// strings; `ctx` a live context.
    pub unsafe extern "C" fn TS_CONF_set_signer_key(conf: *mut CONF, section: *const c_char, key: *const c_char, pass: *const c_char, ctx: *mut TS_RESP_CTX) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let key = unsafe { value_or(conf, section, key, c"signer_key") };
        if key.is_null() {
            return 0;
        }
        // SAFETY: C strings.
        let k = unsafe { TS_CONF_load_key(key, pass) };
        // SAFETY: the caller's context; the key.
        let ok = !k.is_null() && unsafe { TS_RESP_CTX_set_signer_key(ctx, k) } != 0;
        // SAFETY: loaded here, or NULL.
        unsafe { EVP_PKEY_free(k) };
        c_int::from(ok)
    }
}

/// The digest named `name` (the section's `tag`), or NULL with the error.
///
/// # Safety
/// `name` is a C string; `section` NULL or one.
unsafe fn digest(section: *const c_char, name: *const c_char, tag: &CStr) -> *const EVP_MD {
    // SAFETY: the caller's name.
    let md = unsafe { EVP_get_digestbyname(name) };
    if md.is_null() {
        // SAFETY: as above.
        unsafe { invalid(section, tag) };
    }
    md
}

ffi_export! {
    /// Sets the signature's digest to `md` or the section's `signer_digest`: 1, or 0.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `section` and `md` NULL or C strings; `ctx` a
    /// live context.
    pub unsafe extern "C" fn TS_CONF_set_signer_digest(conf: *mut CONF, section: *const c_char, md: *const c_char, ctx: *mut TS_RESP_CTX) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let md = unsafe { value_or(conf, section, md, c"signer_digest") };
        if md.is_null() {
            return 0;
        }
        // SAFETY: C strings.
        let m = unsafe { digest(section, md, c"signer_digest") };
        // SAFETY: the caller's context; a static digest.
        c_int::from(!m.is_null() && unsafe { TS_RESP_CTX_set_signer_digest(ctx, m) } != 0)
    }
}

ffi_export! {
    /// Sets the default policy to `policy` or the section's `default_policy`: 1, or 0.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `section` and `policy` NULL or C strings; `ctx`
    /// a live context.
    pub unsafe extern "C" fn TS_CONF_set_def_policy(conf: *mut CONF, section: *const c_char, policy: *const c_char, ctx: *mut TS_RESP_CTX) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let policy = unsafe { value_or(conf, section, policy, c"default_policy") };
        if policy.is_null() {
            return 0;
        }
        // SAFETY: a C string.
        let obj = unsafe { OBJ_txt2obj(policy, 0) };
        if obj.is_null() {
            // SAFETY: as above.
            unsafe { invalid(section, c"default_policy") };
            return 0;
        }
        // SAFETY: the caller's context; the object.
        let ok = unsafe { TS_RESP_CTX_set_def_policy(ctx, obj) } != 0;
        // SAFETY: made here.
        unsafe { ASN1_OBJECT_free(obj) };
        c_int::from(ok)
    }
}

/// The section's `tag` as a list of values: `Ok(NULL)` when it is not set (and `required` is
/// false), or `Err` with the error.
///
/// # Safety
/// `conf` is NULL or a live configuration; `section` NULL or a C string.
unsafe fn list_of(
    conf: *const CONF,
    section: *const c_char,
    tag: &CStr,
    required: bool,
) -> Result<*mut stack_st_CONF_VALUE, ()> {
    // SAFETY: the caller's guarantee.
    let s = unsafe { get(conf, section, tag) };
    if s.is_null() {
        if required {
            // SAFETY: as above.
            unsafe { lookup_fail(section, tag) };
            return Err(());
        }
        return Ok(ptr::null_mut());
    }
    // SAFETY: the configuration's string.
    let list = unsafe { X509V3_parse_list(s) };
    if list.is_null() {
        // SAFETY: as above.
        unsafe { invalid(section, tag) };
        return Err(());
    }
    Ok(list)
}

/// The values of a list (none for NULL).
///
/// # Safety
/// `list` is NULL or a live list, alive while the values are used.
unsafe fn values<'a>(list: *mut stack_st_CONF_VALUE) -> impl Iterator<Item = &'a CONF_VALUE> {
    // SAFETY: the caller's list, or NULL (0).
    let n = unsafe { OPENSSL_sk_num(list.cast()) };
    (0..n.max(0)).filter_map(move |i| {
        // SAFETY: as above, an index in range.
        let v = unsafe { OPENSSL_sk_value(list.cast(), i) }.cast::<CONF_VALUE>();
        // SAFETY: a value of the list.
        unsafe { v.as_ref() }
    })
}

/// The C string's bytes, or `None` for NULL.
///
/// # Safety
/// `p` is NULL or a C string that outlives the bytes.
unsafe fn cstr<'a>(p: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes())
}

/// A value's value, or else its name.
fn value_of(v: &CONF_VALUE) -> *const c_char {
    if v.value.is_null() { v.name } else { v.value }
}

/// Frees a list of values.
///
/// # Safety
/// `list` is NULL or a list made by `X509V3_parse_list`.
unsafe fn free_list(list: *mut stack_st_CONF_VALUE) {
    // SAFETY: the caller's list.
    unsafe { OPENSSL_sk_pop_free(list.cast(), Some(conf_value_free)) };
}

ffi_export! {
    /// Adds the section's `other_policies`, if any, to the acceptable ones: 1, or 0.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `section` NULL or a C string; `ctx` a live
    /// context.
    pub unsafe extern "C" fn TS_CONF_set_policies(conf: *mut CONF, section: *const c_char, ctx: *mut TS_RESP_CTX) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Ok(list) = (unsafe { list_of(conf, section, c"other_policies", false) }) else { return 0 };
        let mut ok = true;
        // SAFETY: the list made here.
        for v in unsafe { values(list) } {
            // SAFETY: a value's C string.
            let obj = unsafe { OBJ_txt2obj(value_of(v), 0) };
            if obj.is_null() {
                // SAFETY: the caller's section.
                unsafe { invalid(section, c"other_policies") };
                ok = false;
                break;
            }
            // SAFETY: the caller's context; the object.
            ok = unsafe { TS_RESP_CTX_add_policy(ctx, obj) } != 0;
            // SAFETY: made here.
            unsafe { ASN1_OBJECT_free(obj) };
            if !ok {
                break;
            }
        }
        // SAFETY: as above.
        unsafe { free_list(list) };
        c_int::from(ok)
    }
}

ffi_export! {
    /// Adds the section's `digests` (at least one) to the acceptable ones: 1, or 0.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `section` NULL or a C string; `ctx` a live
    /// context.
    pub unsafe extern "C" fn TS_CONF_set_digests(conf: *mut CONF, section: *const c_char, ctx: *mut TS_RESP_CTX) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Ok(list) = (unsafe { list_of(conf, section, c"digests", true) }) else { return 0 };
        // SAFETY: the list made here.
        let mut ok = unsafe { OPENSSL_sk_num(list.cast()) } > 0;
        if !ok {
            // SAFETY: the caller's section.
            unsafe { invalid(section, c"digests") };
        }
        if ok {
            // SAFETY: as above.
            for v in unsafe { values(list) } {
                // SAFETY: a value's C string; the caller's section.
                let md = unsafe { digest(section, value_of(v), c"digests") };
                // SAFETY: the caller's context; a static digest.
                ok = !md.is_null() && unsafe { TS_RESP_CTX_add_md(ctx, md) } != 0;
                if !ok {
                    break;
                }
            }
        }
        // SAFETY: as above.
        unsafe { free_list(list) };
        c_int::from(ok)
    }
}

ffi_export! {
    /// Sets the accuracy from the section's `accuracy` (`secs`, `millisecs`, `microsecs`):
    /// 1, or 0.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `section` NULL or a C string; `ctx` a live
    /// context.
    pub unsafe extern "C" fn TS_CONF_set_accuracy(conf: *mut CONF, section: *const c_char, ctx: *mut TS_RESP_CTX) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Ok(list) = (unsafe { list_of(conf, section, c"accuracy", false) }) else { return 0 };
        let (mut secs, mut millis, mut micros) = (0, 0, 0);
        let mut ok = true;
        // SAFETY: the list made here.
        for v in unsafe { values(list) } {
            // SAFETY: a value's name, a C string.
            let name = unsafe { cstr(v.name) };
            // SAFETY: its value, one or NULL.
            let value = unsafe { cstr(v.value) };
            let slot = match name.unwrap_or_default() {
                b"secs" => &mut secs,
                b"millisecs" => &mut millis,
                b"microsecs" => &mut micros,
                _ => {
                    // SAFETY: the caller's section.
                    unsafe { invalid(section, c"accuracy") };
                    ok = false;
                    break;
                }
            };
            if let Some(value) = value {
                *slot = atoi(value);
            }
        }
        // SAFETY: the caller's context.
        ok = ok && unsafe { TS_RESP_CTX_set_accuracy(ctx, secs, millis, micros) } != 0;
        // SAFETY: as above.
        unsafe { free_list(list) };
        c_int::from(ok)
    }
}

ffi_export! {
    /// Sets the time's fractional digits from the section's `clock_precision_digits` (0 when
    /// not set): 1, or 0.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `section` NULL or a C string; `ctx` a live
    /// context.
    pub unsafe extern "C" fn TS_CONF_set_clock_precision_digits(conf: *const CONF, section: *const c_char, ctx: *mut TS_RESP_CTX) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // `_CONF_get_number`: the number, or 0 (with no error) when it is not one.
        let mut digits: c_long = 0;
        // SAFETY: no requirements.
        unsafe { ERR_set_mark() };
        // SAFETY: the caller's guarantee; `digits`.
        let status = unsafe { NCONF_get_number_e(conf, section, c"clock_precision_digits".as_ptr(), &raw mut digits) };
        // SAFETY: the mark set above.
        unsafe { ERR_pop_to_mark() };
        if status == 0 {
            digits = 0;
        }
        let Some(d) = c_uint::try_from(digits).ok().filter(|&d| d <= TS_MAX_CLOCK_PRECISION_DIGITS.cast_unsigned()) else {
            // SAFETY: the caller's section.
            unsafe { invalid(section, c"clock_precision_digits") };
            return 0;
        };
        // SAFETY: the caller's context.
        unsafe { TS_RESP_CTX_set_clock_precision_digits(ctx, d) }
    }
}

/// `ts_CONF_add_flag`: the flag, when the section's `field` is `yes` (`no` and unset leave
/// it).
///
/// # Safety
/// `conf` is NULL or a live configuration; `section` NULL or a C string; `ctx` a live context.
unsafe fn add_flag(
    conf: *const CONF,
    section: *const c_char,
    field: &CStr,
    flag: c_int,
    ctx: *mut TS_RESP_CTX,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let v = unsafe { get(conf, section, field) };
    if v.is_null() {
        return 1;
    }
    // SAFETY: the configuration's string.
    match unsafe { CStr::from_ptr(v) }.to_bytes() {
        // SAFETY: the caller's context.
        b"yes" => unsafe { TS_RESP_CTX_add_flags(ctx, flag) },
        b"no" => {}
        _ => {
            // SAFETY: the caller's section.
            unsafe { invalid(section, field) };
            return 0;
        }
    }
    1
}

ffi_export! {
    /// Adds `TS_ORDERING` when the section's `ordering` is `yes`: 1, or 0.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `section` NULL or a C string; `ctx` a live
    /// context.
    pub unsafe extern "C" fn TS_CONF_set_ordering(conf: *mut CONF, section: *const c_char, ctx: *mut TS_RESP_CTX) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { add_flag(conf, section, c"ordering", TS_ORDERING, ctx) }
    }
}

ffi_export! {
    /// Adds `TS_TSA_NAME` when the section's `tsa_name` is `yes`: 1, or 0.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `section` NULL or a C string; `ctx` a live
    /// context.
    pub unsafe extern "C" fn TS_CONF_set_tsa_name(conf: *mut CONF, section: *const c_char, ctx: *mut TS_RESP_CTX) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { add_flag(conf, section, c"tsa_name", TS_TSA_NAME, ctx) }
    }
}

ffi_export! {
    /// Adds `TS_ESS_CERT_ID_CHAIN` when the section's `ess_cert_id_chain` is `yes`: 1, or 0.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `section` NULL or a C string; `ctx` a live
    /// context.
    pub unsafe extern "C" fn TS_CONF_set_ess_cert_id_chain(conf: *mut CONF, section: *const c_char, ctx: *mut TS_RESP_CTX) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { add_flag(conf, section, c"ess_cert_id_chain", TS_ESS_CERT_ID_CHAIN, ctx) }
    }
}

ffi_export! {
    /// Sets the signing-certificate digest to the section's `ess_cert_id_alg` (SHA-256 when
    /// not set): 1, or 0.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `section` NULL or a C string; `ctx` a live
    /// context.
    pub unsafe extern "C" fn TS_CONF_set_ess_cert_id_digest(conf: *mut CONF, section: *const c_char, ctx: *mut TS_RESP_CTX) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let mut md = unsafe { get(conf, section, c"ess_cert_id_alg") }.cast_const();
        if md.is_null() {
            md = c"sha256".as_ptr();
        }
        // SAFETY: C strings.
        let m = unsafe { digest(section, md, c"ess_cert_id_alg") };
        // SAFETY: the caller's context; a static digest.
        c_int::from(!m.is_null() && unsafe { TS_RESP_CTX_set_ess_cert_id_digest(ctx, m) } != 0)
    }
}
