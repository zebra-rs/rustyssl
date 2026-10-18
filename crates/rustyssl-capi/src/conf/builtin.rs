//! The built-in configuration modules (`OPENSSL_load_builtin_modules`): `oid_section`,
//! `stbl_section`, `engines`, `alg_section`, `ssl_conf`, `providers`, and `random`, as
//! `asn_moid.c`, `asn_mstbl.c`, `eng_cnf.c`, `evp_cnf.c`, `conf_ssl.c`, `provider_conf.c`, and
//! `rand_lib.c` do them.
//!
//! rustyssl has no engines (ENGINE comes later, and only as OpenSSL 3's stubs of it): an
//! `engines` section that needs one fails as `ENGINE_by_id` of an engine that can't be loaded
//! does in OpenSSL, built-in ones too (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_long, c_ulong};
use core::ptr;
use std::ffi::CString;
use std::sync::{Mutex, PoisonError};

use rustyssl_abi::{
    ASN1_R_ADDING_OBJECT, ASN1_R_ERROR_LOADING_SECTION, ASN1_R_INVALID_STRING_TABLE_VALUE,
    ASN1_R_INVALID_VALUE, CONF, CONF_IMODULE, CONF_R_RECURSIVE_SECTION_REFERENCE,
    CONF_R_SSL_COMMAND_SECTION_EMPTY, CONF_R_SSL_COMMAND_SECTION_NOT_FOUND,
    CONF_R_SSL_SECTION_EMPTY, CONF_R_SSL_SECTION_NOT_FOUND, CONF_VALUE,
    CRYPTO_R_PROVIDER_SECTION_ERROR, CRYPTO_R_RANDOM_SECTION_ERROR,
    CRYPTO_R_UNKNOWN_NAME_IN_RANDOM_SECTION, DSO_R_LOAD_FAILED, ENGINE_R_DSO_NOT_FOUND,
    ENGINE_R_ENGINE_CONFIGURATION_ERROR, ENGINE_R_ENGINE_SECTION_ERROR,
    ENGINE_R_ENGINES_SECTION_ERROR, ENGINE_R_NO_SUCH_ENGINE, ERR_LIB_ASN1, ERR_LIB_CONF,
    ERR_LIB_CRYPTO, ERR_LIB_DSO, ERR_LIB_ENGINE, ERR_LIB_EVP, ERR_R_ASN1_LIB, ERR_R_INTERNAL_ERROR,
    EVP_R_ERROR_LOADING_SECTION, EVP_R_SET_DEFAULT_PROPERTY_FAILURE, EVP_R_UNKNOWN_OPTION,
    NID_undef, OPENSSL_STACK, OSSL_LIB_CTX, STABLE_FLAGS_CLEAR, STABLE_NO_MASK,
};

use super::modules::{CONF_imodule_get_value, FinishFn, InitFn, add_builtin};
use super::{NCONF_get_section, NCONF_get0_libctx, bytes};
use crate::err;
use crate::ffi::ffi_export;
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value};

/// The entries of a section stack (NULL for none), read as they're asked for.
///
/// # Safety
/// `sk` is NULL or a live stack of `CONF_VALUE`s that outlives the use.
unsafe fn entries<'a>(
    sk: *mut rustyssl_abi::stack_st_CONF_VALUE,
) -> impl Iterator<Item = &'a CONF_VALUE> {
    let sk = sk.cast::<OPENSSL_STACK>();
    // SAFETY: the caller's guarantee.
    let n = unsafe { OPENSSL_sk_num(sk) };
    (0..n.max(0)).filter_map(move |i| {
        // SAFETY: the caller's guarantee; an index within it.
        let v = unsafe { OPENSSL_sk_value(sk, i) }.cast::<CONF_VALUE>();
        // SAFETY: an entry of the stack.
        unsafe { v.as_ref() }
    })
}

/// The section the module instance's value names.
///
/// # Safety
/// `md` is a live instance; `cnf` a live configuration.
unsafe fn module_section(
    md: *mut CONF_IMODULE,
    cnf: *const CONF,
) -> *mut rustyssl_abi::stack_st_CONF_VALUE {
    // SAFETY: the caller's guarantee.
    let value = unsafe { CONF_imodule_get_value(md) };
    // SAFETY: the caller's configuration, and the instance's string.
    unsafe { NCONF_get_section(cnf, value) }
}

/// A value's string, or empty for NULL.
///
/// # Safety
/// `s` is NULL or a C string.
unsafe fn text<'a>(s: *const c_char) -> &'a [u8] {
    // SAFETY: the caller's guarantee.
    unsafe { bytes(s) }.unwrap_or_default()
}

/// `skip_dot`: what follows the first `.`, or all of it.
fn skip_dot(name: &[u8]) -> &[u8] {
    name.iter()
        .position(|&c| c == b'.')
        .and_then(|i| name.get(i.saturating_add(1)..))
        .unwrap_or(name)
}

/// Data of OpenSSL's `name=%s, value=%s` (and other) forms.
fn data(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// `ossl_isspace`.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

// --- oid_section (`asn_moid.c`) ---

/// `do_create`: `name = 1.2.3` or `name = long name, 1.2.3` as a new object.
fn do_create(value: &[u8], name: &[u8]) -> bool {
    let (ln, ostr): (Vec<u8>, &[u8]) = match value.iter().rposition(|&c| c == b',') {
        None => (name.to_vec(), value),
        Some(0) => (name.to_vec(), value.get(1..).unwrap_or_default()),
        Some(p) => {
            let mut ostr = value.get(p.saturating_add(1)..).unwrap_or_default();
            if ostr.is_empty() {
                return false;
            }
            let skip = ostr.iter().take_while(|&&c| is_space(c)).count();
            ostr = ostr.get(skip..).unwrap_or_default();
            let lead = value.iter().take_while(|&&c| is_space(c)).count();
            let mut end = p;
            loop {
                let Some(back) = end.checked_sub(1) else {
                    return false;
                };
                if !value.get(back).is_some_and(|&c| is_space(c)) {
                    break;
                }
                if back == lead {
                    return false;
                }
                end = back;
            }
            (value.get(lead..end).unwrap_or_default().to_vec(), ostr)
        }
    };
    let (Ok(ostr), Ok(sn), Ok(ln)) = (CString::new(ostr), CString::new(name), CString::new(ln))
    else {
        return false;
    };
    // SAFETY: C strings.
    unsafe { crate::objects::OBJ_create(ostr.as_ptr(), sn.as_ptr(), ln.as_ptr()) != NID_undef }
}

/// `oid_module_init`.
unsafe extern "C" fn oid_module_init(md: *mut CONF_IMODULE, cnf: *const CONF) -> c_int {
    // SAFETY: the module's instance and configuration.
    let section = unsafe { module_section(md, cnf) };
    if section.is_null() {
        err::raise(
            ERR_LIB_ASN1,
            ASN1_R_ERROR_LOADING_SECTION,
            "oid_module_init",
        );
        return 0;
    }
    // SAFETY: the configuration's section.
    for v in unsafe { entries(section) } {
        // SAFETY: the entry's strings.
        if !do_create(unsafe { text(v.value) }, unsafe { text(v.name) }) {
            err::raise(ERR_LIB_ASN1, ASN1_R_ADDING_OBJECT, "oid_module_init");
            return 0;
        }
    }
    1
}

unsafe extern "C" fn oid_module_finish(_md: *mut CONF_IMODULE) {}

// --- stbl_section (`asn_mstbl.c`) ---

/// `X509V3_conf_free` as a stack's free function.
unsafe extern "C" fn conf_free_item(item: *mut core::ffi::c_void) {
    // SAFETY: an item of a stack of CONF_VALUEs.
    unsafe { crate::x509v3::X509V3_conf_free(item.cast()) };
}

/// `strtoul(s, &end, 0)` with `*end` required to be the end.
fn strtoul_whole(s: &CStr) -> Option<c_long> {
    let mut end: *mut c_char = ptr::null_mut();
    // SAFETY: a C string and a local.
    let v = unsafe { libc::strtoul(s.as_ptr(), &raw mut end, 0) };
    // SAFETY: strtoul leaves `end` within the string.
    if end.is_null() || unsafe { *end } != 0 {
        return None;
    }
    // `long tbl_min = strtoul(...)`: the C conversion.
    Some(c_long::from_ne_bytes(v.to_ne_bytes()))
}

/// `do_tcreate`: `oid_name = min:N, max:N, mask:..., flags:...` as a string table entry.
///
/// # Safety
/// `value` and `name` are C strings.
unsafe fn do_tcreate(value: *const c_char, name: *const c_char) -> bool {
    // SAFETY: the caller's guarantee.
    let mut nid = unsafe { crate::objects::OBJ_sn2nid(name) };
    if nid == NID_undef {
        // SAFETY: as above.
        nid = unsafe { crate::objects::OBJ_ln2nid(name) };
    }
    let (mut min, mut max): (c_long, c_long) = (-1, -1);
    let (mut mask, mut flags): (c_ulong, c_ulong) = (0, 0);
    let mut lst = ptr::null_mut();
    let mut failed_at: Option<*const CONF_VALUE> = None;
    let ok = 'parse: {
        if nid == NID_undef {
            break 'parse false;
        }
        // SAFETY: the caller's string.
        lst = unsafe { crate::x509v3::X509V3_parse_list(value) };
        if lst.is_null() {
            break 'parse false;
        }
        // SAFETY: the list just made.
        for cnf in unsafe { entries(lst) } {
            failed_at = Some(cnf);
            if cnf.value.is_null() {
                break 'parse false;
            }
            // SAFETY: the entry's strings.
            let (n, v) = (unsafe { CStr::from_ptr(cnf.name) }, unsafe {
                CStr::from_ptr(cnf.value)
            });
            match n.to_bytes() {
                b"min" => match strtoul_whole(v) {
                    Some(x) => min = x,
                    None => break 'parse false,
                },
                b"max" => match strtoul_whole(v) {
                    Some(x) => max = x,
                    None => break 'parse false,
                },
                b"mask" => {
                    // SAFETY: a C string and a local.
                    if unsafe { crate::asn1::text::ASN1_str2mask(v.as_ptr(), &raw mut mask) } == 0
                        || mask == 0
                    {
                        break 'parse false;
                    }
                }
                b"flags" => match v.to_bytes() {
                    b"nomask" => flags = c_ulong::from(STABLE_NO_MASK.cast_unsigned()),
                    b"none" => flags = c_ulong::from(STABLE_FLAGS_CLEAR.cast_unsigned()),
                    _ => break 'parse false,
                },
                _ => break 'parse false,
            }
        }
        true
    };
    let rv = if ok {
        // SAFETY: no preconditions.
        let added = unsafe { crate::asn1::text::ASN1_STRING_TABLE_add(nid, min, max, mask, flags) };
        if added == 0 {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, "do_tcreate");
        }
        added != 0
    } else {
        // SAFETY: an entry of the list, or the caller's strings.
        let d = match failed_at.and_then(|c| unsafe { c.as_ref() }) {
            Some(c) => {
                let v = if c.value.is_null() {
                    value
                } else {
                    c.value.cast_const()
                };
                // SAFETY: as above.
                data(&[b"field=", unsafe { text(c.name) }, b", value=", unsafe {
                    text(v)
                }])
            }
            // SAFETY: as above.
            None => data(&[b"name=", unsafe { text(name) }, b", value=", unsafe {
                text(value)
            }]),
        };
        err::raise_with_bytes(
            ERR_LIB_ASN1,
            ASN1_R_INVALID_STRING_TABLE_VALUE,
            "do_tcreate",
            &d,
        );
        false
    };
    // SAFETY: the list made here, with its entries.
    unsafe { OPENSSL_sk_pop_free(lst.cast(), Some(conf_free_item)) };
    rv
}

/// `stbl_module_init`.
unsafe extern "C" fn stbl_module_init(md: *mut CONF_IMODULE, cnf: *const CONF) -> c_int {
    // SAFETY: the module's instance and configuration.
    let section = unsafe { module_section(md, cnf) };
    if section.is_null() {
        err::raise(
            ERR_LIB_ASN1,
            ASN1_R_ERROR_LOADING_SECTION,
            "stbl_module_init",
        );
        return 0;
    }
    // SAFETY: the configuration's section.
    for v in unsafe { entries(section) } {
        // SAFETY: the entry's strings.
        if !unsafe { do_tcreate(v.value, v.name) } {
            err::raise(ERR_LIB_ASN1, ASN1_R_INVALID_VALUE, "stbl_module_init");
            return 0;
        }
    }
    1
}

/// `stbl_module_finish`.
unsafe extern "C" fn stbl_module_finish(_md: *mut CONF_IMODULE) {
    // SAFETY: no preconditions.
    unsafe { crate::asn1::text::ASN1_STRING_TABLE_cleanup() };
}

// --- engines (`eng_cnf.c`) ---

/// The ENGINE ex_data index OpenSSL's dynamic engine reserves at its first use, once per
/// process, for its per-engine data; reserved here too, so applications' indexes match.
static DYNAMIC_EX_INDEX: std::sync::Once = std::sync::Once::new();

/// The errors OpenSSL raises when the dynamic engine can't load the library `file`.
fn engine_load_failed(file: &[u8]) {
    DYNAMIC_EX_INDEX.call_once(|| {
        // SAFETY: no functions for the index.
        unsafe {
            crate::ex_data::CRYPTO_get_ex_new_index(
                rustyssl_abi::CRYPTO_EX_INDEX_ENGINE,
                0,
                ptr::null_mut(),
                None,
                None,
                None,
            )
        };
    });
    let d = data(&[b"filename(", file, b"): rustyssl has no engines"]);
    err::raise_with_bytes(ERR_LIB_DSO, DSO_R_LOAD_FAILED, "dlfcn_load", &d);
    err::raise(ERR_LIB_DSO, DSO_R_LOAD_FAILED, "DSO_load");
    err::raise(ERR_LIB_ENGINE, ENGINE_R_DSO_NOT_FOUND, "dynamic_load");
}

/// `ENGINE_by_id` of an engine there isn't: the dynamic engine's attempt to load it from the
/// engines directory, then `ENGINE_R_NO_SUCH_ENGINE`.
pub(crate) fn engine_by_id_failed(id: &[u8]) {
    let dir = crate::init::safe_getenv(c"OPENSSL_ENGINES")
        .unwrap_or_else(|| crate::version::enginesdir().to_owned());
    #[cfg(target_os = "macos")]
    let ext: &[u8] = b".dylib";
    #[cfg(not(target_os = "macos"))]
    let ext: &[u8] = b".so";
    let file = if id.contains(&b'/') {
        id.to_vec()
    } else {
        data(&[dir.as_bytes(), b"/", id, ext])
    };
    engine_load_failed(&file);
    err::raise_with_bytes(
        ERR_LIB_ENGINE,
        ENGINE_R_NO_SUCH_ENGINE,
        "ENGINE_by_id",
        &data(&[b"id=", id]),
    );
}

/// `int_engine_configure`: an engine's section. With no engines, any command but the pseudo
/// ones (`engine_id`, `soft_load`) needs an engine there isn't.
///
/// # Safety
/// `cnf` is a live configuration; `value` a C string.
unsafe fn engine_configure(name: &[u8], value: *const c_char, cnf: *const CONF) -> bool {
    let mut name = skip_dot(name).to_vec();
    // SAFETY: the caller's guarantee.
    let ecmds = unsafe { NCONF_get_section(cnf, value) };
    if ecmds.is_null() {
        err::raise(
            ERR_LIB_ENGINE,
            ENGINE_R_ENGINE_SECTION_ERROR,
            "int_engine_configure",
        );
        return false;
    }
    let mut soft = false;
    // SAFETY: the configuration's section.
    for ecmd in unsafe { entries(ecmds) } {
        // SAFETY: the entry's strings.
        let (full, cvalue) = (unsafe { text(ecmd.name) }, unsafe { text(ecmd.value) });
        match skip_dot(full) {
            b"engine_id" => name = cvalue.to_vec(),
            b"soft_load" => soft = true,
            b"dynamic_path" => engine_load_failed(cvalue),
            _ => {
                engine_by_id_failed(&name);
                if soft {
                    // SAFETY: no preconditions.
                    unsafe { crate::err::ERR_clear_error() };
                    return true;
                }
            }
        }
        if !matches!(skip_dot(full), b"engine_id" | b"soft_load") {
            // SAFETY: the entry's section.
            let d = data(&[
                b"section=",
                unsafe { text(ecmd.section) },
                b", name=",
                full,
                b", value=",
                cvalue,
            ]);
            err::raise_with_bytes(
                ERR_LIB_ENGINE,
                ENGINE_R_ENGINE_CONFIGURATION_ERROR,
                "int_engine_configure",
                &d,
            );
            return false;
        }
    }
    true
}

/// `int_engine_module_init`.
unsafe extern "C" fn engine_module_init(md: *mut CONF_IMODULE, cnf: *const CONF) -> c_int {
    // SAFETY: the module's instance and configuration.
    let elist = unsafe { module_section(md, cnf) };
    if elist.is_null() {
        err::raise(
            ERR_LIB_ENGINE,
            ENGINE_R_ENGINES_SECTION_ERROR,
            "int_engine_module_init",
        );
        return 0;
    }
    // SAFETY: the configuration's section.
    for v in unsafe { entries(elist) } {
        // SAFETY: the entry's string.
        let name = unsafe { text(v.name) };
        // SAFETY: the entry's value, and the configuration.
        if !unsafe { engine_configure(name, v.value, cnf) } {
            return 0;
        }
    }
    1
}

/// `int_engine_module_finish`: no engines were initialized.
unsafe extern "C" fn engine_module_finish(_md: *mut CONF_IMODULE) {}

// --- alg_section (`evp_cnf.c`) ---

/// `alg_module_init`: `fips_mode` and `default_properties` for the configuration's context.
unsafe extern "C" fn alg_module_init(md: *mut CONF_IMODULE, cnf: *const CONF) -> c_int {
    // SAFETY: the module's instance and configuration.
    let section = unsafe { module_section(md, cnf) };
    if section.is_null() {
        err::raise(ERR_LIB_EVP, EVP_R_ERROR_LOADING_SECTION, "alg_module_init");
        return 0;
    }
    // SAFETY: the configuration.
    let libctx = unsafe { NCONF_get0_libctx(cnf) };
    // SAFETY: the configuration's section.
    for oval in unsafe { entries(section) } {
        // SAFETY: the entry's strings.
        match unsafe { text(oval.name) } {
            b"fips_mode" => {
                let mut m: c_int = 0;
                // SAFETY: the entry, and a local.
                if unsafe { crate::x509v3::X509V3_get_value_bool(oval, &raw mut m) } == 0 {
                    return 0;
                }
                // SAFETY: the configuration's context.
                if !unsafe { crate::property::enable_fips_from_conf(libctx, m > 0) } {
                    err::raise(
                        ERR_LIB_EVP,
                        EVP_R_SET_DEFAULT_PROPERTY_FAILURE,
                        "alg_module_init",
                    );
                    return 0;
                }
            }
            b"default_properties" => {
                // SAFETY: the entry's value.
                let v = unsafe { CStr::from_ptr(oval.value) };
                // SAFETY: the configuration's context.
                if !unsafe { crate::property::set_default_from_conf(libctx, v) } {
                    err::raise(
                        ERR_LIB_EVP,
                        EVP_R_SET_DEFAULT_PROPERTY_FAILURE,
                        "alg_module_init",
                    );
                    return 0;
                }
            }
            _ => {
                // SAFETY: the entry's strings.
                let d = data(
                    &[b"name=", unsafe { text(oval.name) }, b", value=", unsafe {
                        text(oval.value)
                    }],
                );
                err::raise_with_bytes(ERR_LIB_EVP, EVP_R_UNKNOWN_OPTION, "alg_module_init", &d);
                return 0;
            }
        }
    }
    1
}

// --- ssl_conf (`conf_ssl.c`) ---

/// A named set of SSL commands from the configuration (`ssl_conf_name_st`), for libssl's
/// `SSL_CTX_config` (`ssl::conf`).
pub(crate) struct SslName {
    /// The set's name (the section line's name).
    pub(crate) name: CString,
    /// The commands and their arguments, in order (a name's leading part up to `.` dropped).
    pub(crate) cmds: Vec<(CString, CString)>,
}

/// The `ssl_conf` module's sets (OpenSSL's `ssl_names`), which `SSL_CTX_config` reads.
pub(crate) static SSL_NAMES: Mutex<Vec<SslName>> = Mutex::new(Vec::new());

/// `ssl_module_free`.
unsafe extern "C" fn ssl_module_free(_md: *mut CONF_IMODULE) {
    SSL_NAMES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
}

/// `ssl_module_init`: the section's lines name sections of commands, kept for libssl.
unsafe extern "C" fn ssl_module_init(md: *mut CONF_IMODULE, cnf: *const CONF) -> c_int {
    // SAFETY: the module's instance.
    let section = unsafe { CONF_imodule_get_value(md) };
    // SAFETY: the configuration and the instance's value.
    let cmd_lists = unsafe { NCONF_get_section(cnf, section) };
    // SAFETY: the configuration's section, or NULL.
    let n = unsafe { OPENSSL_sk_num(cmd_lists.cast()) };
    if n <= 0 {
        let rcode = if cmd_lists.is_null() {
            CONF_R_SSL_SECTION_NOT_FOUND
        } else {
            CONF_R_SSL_SECTION_EMPTY
        };
        // SAFETY: the instance's value.
        err::raise_with_bytes(
            ERR_LIB_CONF,
            rcode,
            "ssl_module_init",
            &data(&[b"section=", unsafe { text(section) }]),
        );
        // SAFETY: as above.
        unsafe { ssl_module_free(md) };
        return 0;
    }
    // SAFETY: as above.
    unsafe { ssl_module_free(md) };
    let mut names = Vec::new();
    // SAFETY: the configuration's section.
    for sect in unsafe { entries(cmd_lists) } {
        // SAFETY: the configuration, and the entry's value.
        let cmds = unsafe { NCONF_get_section(cnf, sect.value) };
        // SAFETY: as above.
        if unsafe { OPENSSL_sk_num(cmds.cast()) } <= 0 {
            let rcode = if cmds.is_null() {
                CONF_R_SSL_COMMAND_SECTION_NOT_FOUND
            } else {
                CONF_R_SSL_COMMAND_SECTION_EMPTY
            };
            // SAFETY: the entry's strings.
            let d = data(
                &[b"name=", unsafe { text(sect.name) }, b", value=", unsafe {
                    text(sect.value)
                }],
            );
            err::raise_with_bytes(ERR_LIB_CONF, rcode, "ssl_module_init", &d);
            return 0;
        }
        let mut list = Vec::new();
        // SAFETY: the configuration's section.
        for cmd in unsafe { entries(cmds) } {
            // SAFETY: the entry's strings.
            let name = unsafe { text(cmd.name) };
            let name = name
                .iter()
                .position(|&c| c == b'.')
                .and_then(|i| name.get(i.saturating_add(1)..))
                .unwrap_or(name);
            // SAFETY: as above.
            let (Ok(c), Ok(a)) = (CString::new(name), CString::new(unsafe { text(cmd.value) }))
            else {
                return 0;
            };
            list.push((c, a));
        }
        // SAFETY: the entry's string.
        let Ok(name) = CString::new(unsafe { text(sect.name) }) else {
            return 0;
        };
        names.push(SslName { name, cmds: list });
    }
    *SSL_NAMES.lock().unwrap_or_else(PoisonError::into_inner) = names;
    1
}

// --- providers (`provider_conf.c`) ---

/// `provider_conf_parse_bool_setting`.
fn parse_bool(confname: &[u8], value: Option<&[u8]>) -> Option<bool> {
    match value {
        Some(b"1" | b"yes" | b"YES" | b"true" | b"TRUE" | b"on" | b"ON") => Some(true),
        Some(b"0" | b"no" | b"NO" | b"false" | b"FALSE" | b"off" | b"OFF") => Some(false),
        _ => {
            let d = data(&[b"directive ", confname, b" set to unrecognized value"]);
            err::raise_with_bytes(
                ERR_LIB_CRYPTO,
                CRYPTO_R_PROVIDER_SECTION_ERROR,
                "provider_conf_parse_bool_setting",
                &d,
            );
            None
        }
    }
}

/// `provider_conf_params_internal`: a section's values as parameters, `name.sub.key` for those
/// in sections it names (refusing a section reached again through the same value). 1, or
/// below 0 on failure.
///
/// # Safety
/// `cnf` is a live configuration; `value` a C string of it.
unsafe fn conf_params(
    cnf: *const CONF,
    name: Option<&[u8]>,
    value: *const c_char,
    visited: &mut Vec<*const c_char>,
    out: &mut Vec<(CString, CString)>,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let sect = unsafe { NCONF_get_section(cnf, value) };
    if sect.is_null() {
        let Some(name) = name else { return 0 };
        // SAFETY: the caller's guarantee.
        let (Ok(n), Ok(v)) = (CString::new(name), CString::new(unsafe { text(value) })) else {
            return 0;
        };
        out.push((n, v));
        return 1;
    }
    if visited.contains(&value) {
        err::raise(
            ERR_LIB_CONF,
            CONF_R_RECURSIVE_SECTION_REFERENCE,
            "provider_conf_params_internal",
        );
        return -1;
    }
    visited.push(value);
    // OpenSSL's 512-octet buffer.
    let mut prefix = Vec::new();
    if let Some(name) = name {
        prefix.extend_from_slice(name.get(..511).unwrap_or(name));
        if prefix.len() < 511 {
            prefix.push(b'.');
        }
    }
    // SAFETY: the configuration's section.
    for sectconf in unsafe { entries(sect) } {
        // SAFETY: the entry's name.
        let key = unsafe { text(sectconf.name) };
        if prefix.len().saturating_add(key.len()) >= 512 {
            visited.pop();
            return -1;
        }
        let full = data(&[&prefix, key]);
        // SAFETY: the caller's configuration, and the entry's value.
        let rc = unsafe { conf_params(cnf, Some(&full), sectconf.value, visited, out) };
        if rc < 0 {
            visited.pop();
            return rc;
        }
    }
    visited.pop();
    1
}

/// `provider_conf_load`: one provider's section. True unless something fatal failed.
///
/// # Safety
/// `cnf` is a live configuration; `value` a C string of it.
unsafe fn provider_conf_load(
    libctx: *mut OSSL_LIB_CTX,
    name: &[u8],
    value: *const c_char,
    cnf: *const CONF,
) -> bool {
    let mut name = skip_dot(name).to_vec();
    // SAFETY: the caller's guarantee.
    let ecmds = unsafe { NCONF_get_section(cnf, value) };
    if ecmds.is_null() {
        // SAFETY: the caller's string.
        let d = data(&[b"section=", unsafe { text(value) }, b" not found"]);
        err::raise_with_bytes(
            ERR_LIB_CRYPTO,
            CRYPTO_R_PROVIDER_SECTION_ERROR,
            "provider_conf_load",
            &d,
        );
        return false;
    }
    let (mut soft, mut activate) = (false, false);
    let mut path: Option<Vec<u8>> = None;
    // SAFETY: the configuration's section.
    for ecmd in unsafe { entries(ecmds) } {
        // SAFETY: the entry's strings.
        let confname = skip_dot(unsafe { text(ecmd.name) });
        // SAFETY: as above.
        let confvalue = unsafe { bytes(ecmd.value) };
        match confname {
            b"identity" => name = confvalue.unwrap_or_default().to_vec(),
            b"soft_load" => match parse_bool(confname, confvalue) {
                Some(b) => soft = b,
                None => return false,
            },
            b"module" => path = confvalue.map(<[u8]>::to_vec),
            b"activate" => match parse_bool(confname, confvalue) {
                Some(b) => activate = b,
                None => return false,
            },
            _ => {}
        }
    }
    let mut params = Vec::new();
    // SAFETY: the caller's configuration and string.
    let rc = unsafe { conf_params(cnf, None, value, &mut Vec::new(), &mut params) };
    let path = path.and_then(|p| CString::new(p).ok());
    let Ok(cname) = CString::new(name) else {
        return false;
    };
    let ok = if activate {
        let params = if rc == 1 { Ok(params) } else { Err(rc) };
        // SAFETY: the configuration's context.
        unsafe { crate::provider::conf::activate_from_conf(libctx, &cname, path, soft, params) }
    } else if rc < 1 {
        rc
    } else if path.is_some() || !params.is_empty() {
        let params = (!params.is_empty()).then_some(params);
        // SAFETY: as above.
        c_int::from(unsafe {
            crate::provider::conf::add_info_from_conf(libctx, Some(&cname), path, params)
        })
    } else {
        1
    };
    ok >= 0
}

/// `provider_conf_init`.
unsafe extern "C" fn provider_conf_init(md: *mut CONF_IMODULE, cnf: *const CONF) -> c_int {
    // SAFETY: the module's instance and configuration.
    let elist = unsafe { module_section(md, cnf) };
    if elist.is_null() {
        err::raise(
            ERR_LIB_CRYPTO,
            CRYPTO_R_PROVIDER_SECTION_ERROR,
            "provider_conf_init",
        );
        return 0;
    }
    // SAFETY: the configuration.
    let libctx = unsafe { NCONF_get0_libctx(cnf) };
    // SAFETY: the configuration's section.
    for cval in unsafe { entries(elist) } {
        // SAFETY: the entry's name.
        let name = unsafe { text(cval.name) };
        // SAFETY: the configuration's context, the entry's value, and the configuration.
        if !unsafe { provider_conf_load(libctx, name, cval.value, cnf) } {
            return 0;
        }
    }
    1
}

// --- random (`rand_lib.c`) ---

/// `random_conf_init`: the context's generator and seed-source settings.
unsafe extern "C" fn random_conf_init(md: *mut CONF_IMODULE, cnf: *const CONF) -> c_int {
    use crate::rand_lib::{ConfSetting, set_from_conf};
    // SAFETY: the configuration.
    let libctx = unsafe { NCONF_get0_libctx(cnf) };
    // SAFETY: the module's instance and configuration.
    let elist = unsafe { module_section(md, cnf) };
    if elist.is_null() {
        err::raise(
            ERR_LIB_CRYPTO,
            CRYPTO_R_RANDOM_SECTION_ERROR,
            "random_conf_init",
        );
        return 0;
    }
    let mut r = 1;
    // SAFETY: the configuration's section.
    for cval in unsafe { entries(elist) } {
        // SAFETY: the entry's strings.
        let (name, value) = (unsafe { text(cval.name) }, unsafe {
            CStr::from_ptr(cval.value)
        });
        let setting = match name.to_ascii_lowercase().as_slice() {
            b"random" => ConfSetting::Random,
            b"cipher" => ConfSetting::Cipher,
            b"digest" => ConfSetting::Digest,
            b"properties" => ConfSetting::Properties,
            b"seed" => ConfSetting::Seed,
            b"seed_properties" => ConfSetting::SeedProperties,
            b"random_provider" => {
                // SAFETY: the configuration's context, and a C string.
                let prov = unsafe { crate::provider::find_held(libctx, value) };
                if !prov.is_null() {
                    // SAFETY: a provider with our reference.
                    if unsafe { crate::rand_lib::RAND_set1_random_provider(libctx, prov) } == 0 {
                        err::raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR, "random_conf_init");
                        // SAFETY: as above.
                        unsafe { crate::provider::OSSL_PROVIDER_unload(prov) };
                        return 0;
                    }
                    // OpenSSL keeps no reference (and its unload deactivates the provider too).
                    // SAFETY: as above.
                    unsafe { crate::provider::OSSL_PROVIDER_unload(prov) };
                    continue;
                }
                ConfSetting::RandomProviderName
            }
            _ => {
                let d = data(&[b"name=", name, b", value=", value.to_bytes()]);
                err::raise_with_bytes(
                    ERR_LIB_CRYPTO,
                    CRYPTO_R_UNKNOWN_NAME_IN_RANDOM_SECTION,
                    "random_conf_init",
                    &d,
                );
                r = 0;
                continue;
            }
        };
        // SAFETY: the configuration's context.
        if !unsafe { set_from_conf(libctx, setting, value) } {
            return 0;
        }
    }
    r
}

unsafe extern "C" fn random_conf_deinit(_md: *mut CONF_IMODULE) {}

// --- Registering ---

const OID: (&CStr, InitFn, Option<FinishFn>) =
    (c"oid_section", oid_module_init, Some(oid_module_finish));
const STBL: (&CStr, InitFn, Option<FinishFn>) =
    (c"stbl_section", stbl_module_init, Some(stbl_module_finish));
const ENGINES: (&CStr, InitFn, Option<FinishFn>) =
    (c"engines", engine_module_init, Some(engine_module_finish));
const ALG: (&CStr, InitFn, Option<FinishFn>) = (c"alg_section", alg_module_init, None);
const SSL: (&CStr, InitFn, Option<FinishFn>) =
    (c"ssl_conf", ssl_module_init, Some(ssl_module_free));
const PROVIDERS: (&CStr, InitFn, Option<FinishFn>) = (c"providers", provider_conf_init, None);
const RANDOM: (&CStr, InitFn, Option<FinishFn>) =
    (c"random", random_conf_init, Some(random_conf_deinit));

fn add(m: (&CStr, InitFn, Option<FinishFn>)) {
    add_builtin(m.0, m.1, m.2);
}

/// `OPENSSL_load_builtin_modules`, in OpenSSL's order.
pub(crate) fn add_all() {
    for m in [OID, STBL, ENGINES, ALG, SSL, PROVIDERS, RANDOM] {
        add(m);
    }
}

ffi_export! {
    /// Adds the built-in configuration modules (again, if they were added before).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OPENSSL_load_builtin_modules()
    where failure = (), library = ERR_LIB_CONF
    {
        add_all();
    }
}

ffi_export! {
    /// Adds the `oid_section` module.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_add_oid_module()
    where failure = (), library = ERR_LIB_ASN1
    {
        add(OID);
    }
}

ffi_export! {
    /// Adds the `stbl_section` module.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_add_stable_module()
    where failure = (), library = ERR_LIB_ASN1
    {
        add(STBL);
    }
}

ffi_export! {
    /// Adds the `engines` module.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_add_conf_module()
    where failure = (), library = ERR_LIB_ENGINE
    {
        add(ENGINES);
    }
}

ffi_export! {
    /// Adds the `alg_section` module.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_add_alg_module()
    where failure = (), library = ERR_LIB_EVP
    {
        add(ALG);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conf::modules::CONF_modules_load;
    use crate::conf::{NCONF_free, NCONF_load_bio, NCONF_new};

    /// The modules of `text` run: the result and the errors' reasons.
    fn run(text: &[u8], flags: c_ulong) -> (c_int, Vec<c_int>) {
        let len = c_int::try_from(text.len()).unwrap_or(0);
        // SAFETY: no preconditions.
        let conf = unsafe { NCONF_new(ptr::null_mut()) };
        // SAFETY: a buffer of that length.
        let b = unsafe { crate::bio::mem::BIO_new_mem_buf(text.as_ptr().cast(), len) };
        // SAFETY: the configuration and the BIO.
        assert_eq!(unsafe { NCONF_load_bio(conf, b, ptr::null_mut()) }, 1);
        // SAFETY: the loaded configuration.
        let r = unsafe { CONF_modules_load(conf, ptr::null(), flags) };
        let mask = c_ulong::from(rustyssl_abi::ERR_REASON_MASK.cast_unsigned());
        let reasons = err::take_all()
            .iter()
            .map(|e| c_int::try_from(e.code & mask).unwrap_or(0))
            .collect();
        // SAFETY: each freed once.
        unsafe { crate::bio::BIO_free(b) };
        // SAFETY: as above.
        unsafe { NCONF_free(conf) };
        (r, reasons)
    }

    /// docs/DEVIATIONS.md: an `engines` section that needs an engine fails, even for one
    /// OpenSSL builds in (`dynamic`), as `ENGINE_by_id` of an engine that can't be loaded
    /// does; one that only names it, or loads it softly, succeeds as in OpenSSL.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "the engines directory comes from the environment, which reads the process's IDs"
    )]
    fn engines_are_never_found() {
        let (r, reasons) = run(
            b"openssl_conf = init\n[init]\nengines = e\n[e]\nx = f\n[f]\nengine_id = dynamic\ninit = 0\n",
            0,
        );
        assert_eq!(r, -1);
        assert!(reasons.contains(&ENGINE_R_NO_SUCH_ENGINE), "{reasons:?}");
        let (r, _) = run(
            b"openssl_conf = init\n[init]\nengines = e\n[e]\nx = f\n[f]\nengine_id = dynamic\n",
            0,
        );
        assert_eq!(r, 1);
        let (r, reasons) = run(
            b"openssl_conf = init\n[init]\nengines = e\n[e]\nx = f\n[f]\nsoft_load = 1\ninit = 1\n",
            0,
        );
        assert_eq!((r, reasons), (1, Vec::new()));
    }

    /// docs/DEVIATIONS.md: a module that isn't known isn't loaded from a shared library (OpenSSL
    /// loads `lib<name>` and runs its `OPENSSL_init`): the load fails with OpenSSL's errors for
    /// a library that can't be loaded.
    #[test]
    fn unknown_modules_are_not_loaded_from_libraries() {
        let (r, reasons) = run(b"openssl_conf = init\n[init]\nrustyssl_nosuch = v\n", 0);
        assert_eq!(r, -1);
        assert_eq!(
            reasons,
            [
                DSO_R_LOAD_FAILED,
                DSO_R_LOAD_FAILED,
                rustyssl_abi::CONF_R_ERROR_LOADING_DSO,
                rustyssl_abi::CONF_R_UNKNOWN_MODULE_NAME
            ]
        );
    }
}
