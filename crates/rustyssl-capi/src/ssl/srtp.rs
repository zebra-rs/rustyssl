//! The DTLS-SRTP protection profiles (`d1_srtp.c`): the profile lists a context or connection
//! offers (`SSL_CTX_set_tlsext_use_srtp`, `SSL_set_tlsext_use_srtp`), which the core's
//! use_srtp extension sends and matches, and the profile negotiated.

use core::ffi::{CStr, c_char, c_int, c_ulong};
use core::ptr;
use std::sync::OnceLock;

use rustyssl_abi::{
    ERR_LIB_SSL, SRTP_AEAD_AES_128_GCM, SRTP_AEAD_AES_256_GCM, SRTP_AEAD_ARIA_128_GCM,
    SRTP_AEAD_ARIA_256_GCM, SRTP_AES128_CM_SHA1_32, SRTP_AES128_CM_SHA1_80,
    SRTP_ARIA_128_CTR_HMAC_SHA1_32, SRTP_ARIA_128_CTR_HMAC_SHA1_80, SRTP_ARIA_256_CTR_HMAC_SHA1_32,
    SRTP_ARIA_256_CTR_HMAC_SHA1_80, SRTP_DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM,
    SRTP_DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM, SRTP_PROTECTION_PROFILE, SSL, SSL_CTX,
    SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST, SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES,
    SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE, stack_st_SRTP_PROTECTION_PROFILE,
};

use super::conn::{SslState, ctx_of, ssl};
use super::ctx::{self as ctxs, Ctx};
use crate::err;
use crate::ffi::ffi_export;
use crate::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value,
};

/// The profiles OpenSSL knows (`srtp_known_profiles`), in its order.
struct Known([SRTP_PROTECTION_PROFILE; 12]);

// SAFETY: the names are static strings, never written.
unsafe impl Send for Known {}
// SAFETY: as above.
unsafe impl Sync for Known {}

/// The table, at a fixed address (the lists point into it).
fn known() -> &'static [SRTP_PROTECTION_PROFILE] {
    static KNOWN: OnceLock<Known> = OnceLock::new();
    let entry = |name: &'static CStr, id: c_int| SRTP_PROTECTION_PROFILE {
        name: name.as_ptr(),
        id: c_ulong::try_from(id).unwrap_or(0),
    };
    &KNOWN
        .get_or_init(|| {
            Known([
                entry(c"SRTP_AES128_CM_SHA1_80", SRTP_AES128_CM_SHA1_80),
                entry(c"SRTP_AES128_CM_SHA1_32", SRTP_AES128_CM_SHA1_32),
                entry(c"SRTP_AEAD_AES_128_GCM", SRTP_AEAD_AES_128_GCM),
                entry(c"SRTP_AEAD_AES_256_GCM", SRTP_AEAD_AES_256_GCM),
                entry(
                    c"SRTP_DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM",
                    SRTP_DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM,
                ),
                entry(
                    c"SRTP_DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM",
                    SRTP_DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM,
                ),
                entry(
                    c"SRTP_ARIA_128_CTR_HMAC_SHA1_80",
                    SRTP_ARIA_128_CTR_HMAC_SHA1_80,
                ),
                entry(
                    c"SRTP_ARIA_128_CTR_HMAC_SHA1_32",
                    SRTP_ARIA_128_CTR_HMAC_SHA1_32,
                ),
                entry(
                    c"SRTP_ARIA_256_CTR_HMAC_SHA1_80",
                    SRTP_ARIA_256_CTR_HMAC_SHA1_80,
                ),
                entry(
                    c"SRTP_ARIA_256_CTR_HMAC_SHA1_32",
                    SRTP_ARIA_256_CTR_HMAC_SHA1_32,
                ),
                entry(c"SRTP_AEAD_ARIA_128_GCM", SRTP_AEAD_ARIA_128_GCM),
                entry(c"SRTP_AEAD_ARIA_256_GCM", SRTP_AEAD_ARIA_256_GCM),
            ])
        })
        .0
}

/// A profile list (owned stack of pointers into the table), or none.
#[derive(Debug)]
pub(crate) struct Profiles(*mut stack_st_SRTP_PROTECTION_PROFILE);

impl Default for Profiles {
    fn default() -> Self {
        Self(ptr::null_mut())
    }
}

impl Drop for Profiles {
    fn drop(&mut self) {
        // SAFETY: our own stack (its entries are the static table's), or NULL.
        unsafe { OPENSSL_sk_free(self.0.cast()) };
    }
}

/// The entries of a list.
fn entries(list: *mut stack_st_SRTP_PROTECTION_PROFILE) -> Vec<*const SRTP_PROTECTION_PROFILE> {
    // SAFETY: a list of ours, or NULL.
    let n = unsafe { OPENSSL_sk_num(list.cast()) };
    (0..n.max(0))
        .map(|i| {
            // SAFETY: an index of the list.
            unsafe { OPENSSL_sk_value(list.cast(), i) }
                .cast_const()
                .cast()
        })
        .collect()
}

/// `ssl_ctx_make_profiles`: `text`'s colon-separated names as a list, replacing `out`: 0, or 1
/// with the error raised.
fn make_profiles(text: &[u8], out: &mut Profiles) -> c_int {
    // OpenSSL raises these in ssl_ctx_make_profiles, for the connection's too.
    let function = "ssl_ctx_make_profiles";
    // SAFETY: no preconditions.
    let list: *mut stack_st_SRTP_PROTECTION_PROFILE = unsafe { OPENSSL_sk_new_null() }.cast();
    if list.is_null() {
        err::raise(
            ERR_LIB_SSL,
            SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES,
            function,
        );
        return 1;
    }
    let fresh = Profiles(list);
    for name in text.split(|&b| b == b':') {
        let found = known().iter().find(|p| {
            // SAFETY: the table's static names.
            unsafe { CStr::from_ptr(p.name) }.to_bytes() == name
        });
        let Some(p) = found else {
            err::raise(ERR_LIB_SSL, SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE, function);
            return 1;
        };
        let p: *const SRTP_PROTECTION_PROFILE = p;
        if entries(list).contains(&p) {
            err::raise(
                ERR_LIB_SSL,
                SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST,
                function,
            );
            return 1;
        }
        // SAFETY: our list; the entry is static.
        if unsafe { OPENSSL_sk_push(list.cast(), p.cast()) } == 0 {
            err::raise(
                ERR_LIB_SSL,
                SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES,
                function,
            );
            return 1;
        }
    }
    *out = fresh;
    0
}

/// The C string's octets, or `None` for NULL.
///
/// # Safety
/// `p` is NULL or a NUL-terminated string.
unsafe fn text<'a>(p: *const c_char) -> Option<&'a [u8]> {
    if p.is_null() {
        return None;
    }
    // SAFETY: the caller's guarantee.
    Some(unsafe { CStr::from_ptr(p) }.to_bytes())
}

ffi_export! {
    /// Sets the context's SRTP profiles from a colon-separated list: 0 on success, 1 on
    /// failure (OpenSSL's inverted convention).
    ///
    /// # Safety
    /// `ctx` is a live context; `profiles` a string.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_tlsext_use_srtp(ctx: *mut SSL_CTX, profiles: *const c_char) -> c_int
    where failure = 1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::api::is_quic_ctx(ctx) } {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let (Some(c), Some(t)) = (unsafe { ctxs::ctx(ctx) }, unsafe { text(profiles) }) else {
            return 1;
        };
        make_profiles(t, &mut c.state().srtp)
    }
}

ffi_export! {
    /// Sets the connection's SRTP profiles: 0 on success, 1 on failure.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `profiles` a string.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_tlsext_use_srtp(s: *mut SSL, profiles: *const c_char) -> c_int
    where failure = 1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(t)) = (unsafe { ssl(s) }, unsafe { text(profiles) }) else {
            return 1;
        };
        make_profiles(t, &mut x.state().srtp)
    }
}

/// `SSL_get_srtp_profiles`: the connection's list, else its context's, or NULL.
fn profiles(st: &SslState, c: Option<&Ctx>) -> *mut stack_st_SRTP_PROTECTION_PROFILE {
    if !st.srtp.0.is_null() {
        return st.srtp.0;
    }
    c.map_or(ptr::null_mut(), |c| c.state().srtp.0)
}

/// The profile ids offered, in order, for the core's configuration.
pub(crate) fn ids(st: &SslState, c: Option<&Ctx>) -> Vec<u16> {
    entries(profiles(st, c))
        .into_iter()
        .filter_map(|p| {
            // SAFETY: an entry of the static table.
            u16::try_from(unsafe { (*p).id }).ok()
        })
        .collect()
}

ffi_export! {
    /// The SRTP profiles offered (the connection's, else its context's), or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_srtp_profiles(s: *mut SSL) -> *mut stack_st_SRTP_PROTECTION_PROFILE
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return ptr::null_mut() };
        let st = x.state();
        // SAFETY: the connection's context, which it keeps alive.
        let c = unsafe { ctx_of(&st) };
        profiles(&st, c)
    }
}

ffi_export! {
    /// The SRTP profile negotiated, or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_selected_srtp_profile(s: *mut SSL) -> *mut SRTP_PROTECTION_PROFILE
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return ptr::null_mut() };
        let Some(id) = x.state().drv.tls.as_ref().and_then(|c| c.srtp_profile()) else {
            return ptr::null_mut();
        };
        known()
            .iter()
            .find(|p| p.id == c_ulong::from(id))
            .map_or(ptr::null_mut(), |p| ptr::from_ref(p).cast_mut())
    }
}
