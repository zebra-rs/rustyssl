//! A library context's properties (`property(7)`) over `rustyssl_crypto::property`: its
//! numbered names and values, its default query, and `EVP_set_default_properties(3)`,
//! `EVP_get1_default_properties`, and `EVP_default_properties_enable_fips`/`_is_fips_enabled`.
//!
//! As in OpenSSL (`crypto/evp/evp_fetch.c`), setting or reading the defaults first loads the
//! configuration (`OPENSSL_INIT_LOAD_CONFIG`; reading only in the global default context), a
//! query that doesn't parse raises the parser's errors then `EVP_R_DEFAULT_QUERY_PARSE_ERROR`,
//! and a query that parses but has no canonical text (a value missing) fails with
//! `ERR_R_INTERNAL_ERROR`. The properties' lock is never held while the configuration loads.

use core::ffi::{c_char, c_int};
use core::ptr;
use std::ffi::CStr;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    ERR_LIB_EVP, ERR_LIB_PROP, ERR_R_INTERNAL_ERROR, EVP_R_DEFAULT_QUERY_PARSE_ERROR,
    OPENSSL_INIT_LOAD_CONFIG, OSSL_LIB_CTX,
};
use rustyssl_crypto::property::{self, List, Reason, Strings};

use crate::ffi::ffi_export;
use crate::generated::err_strings::{
    PROP_R_NAME_TOO_LONG, PROP_R_NO_MATCHING_STRING_DELIMITER, PROP_R_NO_VALUE,
    PROP_R_NOT_A_DECIMAL_DIGIT, PROP_R_NOT_AN_ASCII_CHARACTER, PROP_R_NOT_AN_HEXADECIMAL_DIGIT,
    PROP_R_NOT_AN_IDENTIFIER, PROP_R_NOT_AN_OCTAL_DIGIT, PROP_R_PARSE_FAILED,
    PROP_R_STRING_TOO_LONG, PROP_R_TRAILING_CHARACTERS,
};
use crate::handle::Held;
use crate::{err, init, libctx, objects};

/// A context's properties.
#[derive(Default)]
pub(crate) struct Properties {
    /// The names and values the context has numbered.
    pub(crate) strings: Strings,
    /// The default query (`EVP_set_default_properties`), if any.
    pub(crate) global: Option<List>,
    /// Parsed property definitions by text (`ossl_prop_defn_get`).
    pub(crate) definitions: std::collections::HashMap<Vec<u8>, List>,
}

/// A context's properties, behind their lock.
#[derive(Default)]
pub(crate) struct Store(Mutex<Properties>);

impl Store {
    pub(crate) fn lock(&self) -> MutexGuard<'_, Properties> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Raises the parser's errors, as OpenSSL's parser does while it parses.
#[track_caller]
pub(crate) fn raise_parse_errors(errors: &[property::Error], function: &str) {
    for e in errors {
        let reason = match e.reason {
            Reason::NameTooLong => PROP_R_NAME_TOO_LONG,
            Reason::NotAnAsciiCharacter => PROP_R_NOT_AN_ASCII_CHARACTER,
            Reason::NotAnHexadecimalDigit => PROP_R_NOT_AN_HEXADECIMAL_DIGIT,
            Reason::NotAnIdentifier => PROP_R_NOT_AN_IDENTIFIER,
            Reason::NotAnOctalDigit => PROP_R_NOT_AN_OCTAL_DIGIT,
            Reason::NotADecimalDigit => PROP_R_NOT_A_DECIMAL_DIGIT,
            Reason::NoMatchingStringDelimiter => PROP_R_NO_MATCHING_STRING_DELIMITER,
            Reason::NoValue => PROP_R_NO_VALUE,
            Reason::ParseFailed => PROP_R_PARSE_FAILED,
            Reason::StringTooLong => PROP_R_STRING_TOO_LONG,
            Reason::TrailingCharacters => PROP_R_TRAILING_CHARACTERS,
        };
        err::raise_with_bytes(ERR_LIB_PROP, reason, function, &e.data);
    }
}

/// `ossl_ctx_global_properties`'s configuration load: false if it failed.
fn load_config() -> bool {
    let opts = u64::try_from(OPENSSL_INIT_LOAD_CONFIG).unwrap_or(0);
    // SAFETY: no settings.
    let r = unsafe { init::OPENSSL_init_crypto(opts, ptr::null()) };
    r == 1
}

/// The context `libctx` stands for.
///
/// # Safety
/// `libctx` is NULL or a live library context.
unsafe fn context(libctx: *mut OSSL_LIB_CTX) -> Option<Held<OSSL_LIB_CTX>> {
    // SAFETY: the caller's guarantee.
    unsafe { libctx::resolve(libctx) }
}

/// Parses `propq` as a query in `ctx`, adding its values; on failure raises the parser's
/// errors and `EVP_R_DEFAULT_QUERY_PARSE_ERROR`.
#[track_caller]
fn parse_default(ctx: &libctx::LibCtx, propq: &[u8], function: &str) -> Option<List> {
    let parsed = property::parse_query(&mut ctx.properties.lock().strings, propq, true);
    raise_parse_errors(&parsed.errors, function);
    if parsed.list.is_none() {
        err::raise(ERR_LIB_EVP, EVP_R_DEFAULT_QUERY_PARSE_ERROR, function);
    }
    parsed.list
}

/// `evp_set_parsed_default_properties`: makes `list` the context's default query, after
/// loading the configuration if `load` and checking that it has canonical text.
#[track_caller]
fn set_parsed(ctx: &libctx::LibCtx, list: Option<List>, load: bool, function: &str) -> bool {
    if load && !load_config() {
        err::raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR, function);
        return false;
    }
    let mut properties = ctx.properties.lock();
    if property::to_text(&properties.strings, list.as_ref()).is_none() {
        drop(properties);
        err::raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR, function);
        return false;
    }
    properties.global = list;
    drop(properties);
    // Choices made under the old defaults are stale (`ossl_method_store_cache_flush_all`).
    ctx.evp.flush();
    true
}

/// `evp_set_default_properties_int(libctx, propq, 0, 0)`, for the configuration's
/// `alg_section`: sets the default query without loading the configuration.
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn set_default_from_conf(libctx: *mut OSSL_LIB_CTX, propq: &CStr) -> bool {
    let name = "evp_set_default_properties_int";
    // SAFETY: the caller's guarantee.
    let Some(ctx) = (unsafe { context(libctx) }) else {
        err::raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR, name);
        return false;
    };
    let Some(list) = parse_default(&ctx, propq.to_bytes(), name) else {
        return false;
    };
    set_parsed(&ctx, Some(list), false, name)
}

/// `evp_default_properties_enable_fips_int(libctx, enable, 0)`, for the configuration's
/// `fips_mode`: merges `fips=yes` (or `-fips`) into the default query without loading the
/// configuration.
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn enable_fips_from_conf(libctx: *mut OSSL_LIB_CTX, enable: bool) -> bool {
    let query: &CStr = if enable { c"fips=yes" } else { c"-fips" };
    // SAFETY: the caller's guarantee.
    let Some(ctx) = (unsafe { context(libctx) }) else {
        err::raise(
            ERR_LIB_EVP,
            ERR_R_INTERNAL_ERROR,
            "evp_default_properties_merge",
        );
        return false;
    };
    if ctx.properties.lock().global.is_none() {
        // SAFETY: the caller's guarantee.
        return unsafe { set_default_from_conf(libctx, query) };
    }
    let Some(list) = parse_default(&ctx, query.to_bytes(), "evp_default_properties_merge") else {
        return false;
    };
    let merged = match &ctx.properties.lock().global {
        Some(current) => property::merge(&list, current),
        None => list,
    };
    set_parsed(&ctx, Some(merged), false, "evp_default_properties_merge")
}

ffi_export! {
    /// Sets the default property query of `libctx` (the thread's default context for NULL),
    /// which every fetch adds to its own; NULL clears it. Returns 1, or 0 if the query doesn't
    /// parse.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `propq` is NULL or a string.
    pub unsafe extern "C" fn EVP_set_default_properties(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let name = "EVP_set_default_properties";
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(libctx) }) else {
            err::raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR, name);
            return 0;
        };
        let list = if propq.is_null() {
            None
        } else {
            // SAFETY: the caller's guarantee.
            let text = unsafe { CStr::from_ptr(propq) }.to_bytes();
            let Some(list) = parse_default(&ctx, text, name) else {
                return 0;
            };
            Some(list)
        };
        c_int::from(set_parsed(&ctx, list, true, name))
    }
}

ffi_export! {
    /// The default property query of `libctx` (the thread's default context for NULL) in
    /// canonical form, allocated for the caller to free with `OPENSSL_free`; "" for none.
    /// NULL on failure.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context.
    pub unsafe extern "C" fn EVP_get1_default_properties(libctx: *mut OSSL_LIB_CTX) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        let name = "EVP_get1_default_properties";
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(libctx) }) else {
            return ptr::null_mut();
        };
        let text = {
            let in_global = libctx::is_global(&ctx);
            if in_global && !load_config() {
                Some(Vec::new())
            } else {
                let properties = ctx.properties.lock();
                property::to_text(&properties.strings, properties.global.as_ref())
            }
        };
        let Some(text) = text else {
            err::raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR, name);
            return ptr::null_mut();
        };
        objects::c_string(&text)
    }
}

ffi_export! {
    /// Adds `fips=yes` (nonzero `enable`) or `-fips` to the default property query of `libctx`
    /// (the thread's default context for NULL), replacing any `fips` term. Returns 1, or 0 on
    /// failure.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context.
    pub unsafe extern "C" fn EVP_default_properties_enable_fips(libctx: *mut OSSL_LIB_CTX, enable: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let name = "EVP_default_properties_enable_fips";
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(libctx) }) else {
            err::raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR, name);
            return 0;
        };
        let query: &[u8] = if enable != 0 { b"fips=yes" } else { b"-fips" };
        if !load_config() {
            // OpenSSL then sets the query as the whole default (without loading again).
            let Some(list) = parse_default(&ctx, query, name) else { return 0 };
            return c_int::from(set_parsed(&ctx, Some(list), false, name));
        }
        let Some(list) = parse_default(&ctx, query, name) else { return 0 };
        let merged = match &ctx.properties.lock().global {
            Some(current) => property::merge(&list, current),
            None => list,
        };
        c_int::from(set_parsed(&ctx, Some(merged), false, name))
    }
}

ffi_export! {
    /// Whether the default property query of `libctx` (the thread's default context for NULL)
    /// requires `fips=yes`.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context.
    pub unsafe extern "C" fn EVP_default_properties_is_fips_enabled(libctx: *mut OSSL_LIB_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(libctx) }) else { return 0 };
        if !load_config() {
            return 0;
        }
        let mut properties = ctx.properties.lock();
        let Properties { strings, global, .. } = &mut *properties;
        c_int::from(property::is_enabled(strings, b"fips", global.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore = "loads the configuration, which calls getgid")]
    fn defaults_round_trip() {
        // SAFETY: no preconditions.
        let ctx = unsafe { libctx::OSSL_LIB_CTX_new() };
        // SAFETY: a live context and a string.
        let r = unsafe { EVP_set_default_properties(ctx, c"Provider=Default, ?fips".as_ptr()) };
        assert_eq!(r, 1);
        // SAFETY: as above.
        let r = unsafe { EVP_default_properties_enable_fips(ctx, 0) };
        assert_eq!(r, 1);
        // SAFETY: a live context.
        let text = unsafe { EVP_get1_default_properties(ctx) };
        // SAFETY: a string from `OPENSSL_malloc`.
        assert_eq!(unsafe { CStr::from_ptr(text) }, c"-fips,provider=default");
        // SAFETY: as above, freed once.
        unsafe { crate::mem::release(text.cast()) };
        // SAFETY: a live context and a string.
        let r = unsafe { EVP_set_default_properties(ctx, c"fips=".as_ptr()) };
        assert_eq!(r, 0);
        // SAFETY: no longer used.
        unsafe { libctx::OSSL_LIB_CTX_free(ctx) };
        err::take_all();
    }
}
