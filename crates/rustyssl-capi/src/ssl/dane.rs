//! DANE (RFC 6698, RFC 7671; `ssl_lib.c`'s `SSL_dane_*`): a context's digests for the TLSA
//! matching types, and a connection's TLSA records, validated and ordered as OpenSSL orders
//! them.
//!
//! The verifier matches the peer against the records (`crate::x509::dane`, given the state by
//! `X509_STORE_CTX_set0_dane`) and leaves its result here: the matching record, the certificate
//! that matched, and its depth, which `SSL_get0_dane_authority` and `SSL_get0_dane_tlsa`
//! report.

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_SSL, ERR_R_CRYPTO_LIB, EVP_MD, EVP_PKEY, NID_sha256, NID_sha512, SSL,
    SSL_CTRL_SET_TLSEXT_HOSTNAME, SSL_CTX, SSL_DANE, SSL_R_CONTEXT_NOT_DANE_ENABLED,
    SSL_R_DANE_ALREADY_ENABLED, SSL_R_DANE_CANNOT_OVERRIDE_MTYPE_FULL, SSL_R_DANE_NOT_ENABLED,
    SSL_R_DANE_TLSA_BAD_CERTIFICATE, SSL_R_DANE_TLSA_BAD_CERTIFICATE_USAGE,
    SSL_R_DANE_TLSA_BAD_DATA_LENGTH, SSL_R_DANE_TLSA_BAD_DIGEST_LENGTH,
    SSL_R_DANE_TLSA_BAD_MATCHING_TYPE, SSL_R_DANE_TLSA_BAD_PUBLIC_KEY,
    SSL_R_DANE_TLSA_BAD_SELECTOR, SSL_R_DANE_TLSA_NULL_DATA, SSL_R_ERROR_SETTING_TLSA_BASE_DOMAIN,
    TLSEXT_NAMETYPE_host_name, X509, X509_V_OK, stack_st_X509,
};

use super::conn::{ctx_of, rustyssl_private_SSL_ctrl, ssl};
use super::ctx::ctx;
use crate::err;
use crate::evp::digest::EVP_MD_get_size;
use crate::evp::legacy_md::EVP_get_digestbyname;
use crate::evp::pkey::EVP_PKEY_free;
use crate::ffi::ffi_export;
use crate::objects::OBJ_nid2sn;
use crate::stack::{OPENSSL_sk_new_null, OPENSSL_sk_push};
use crate::x509::cert::{OSSL_STACK_OF_X509_free, X509_free, X509_get0_pubkey, d2i_X509};
use crate::x509::pubkey::d2i_PUBKEY;
use crate::x509::vpm::X509_VERIFY_PARAM_set1_host;

/// The TLSA certificate usages, selectors, and matching types (`internal/dane.h`):
/// PKIX-TA(0), PKIX-EE(1), DANE-TA(2), DANE-EE(3).
pub(crate) const USAGE_PKIX_TA: u8 = 0;
/// See [`USAGE_PKIX_TA`].
pub(crate) const USAGE_PKIX_EE: u8 = 1;
/// See [`USAGE_PKIX_TA`].
pub(crate) const USAGE_DANE_TA: u8 = 2;
/// See [`USAGE_PKIX_TA`].
pub(crate) const USAGE_DANE_EE: u8 = 3;
/// See [`USAGE_PKIX_TA`].
const USAGE_LAST: u8 = USAGE_DANE_EE;
/// `DANETLS_USAGE_BIT`.
pub(crate) const fn usage_bit(u: u8) -> u32 {
    1 << u
}
/// The usages whose records name trust anchors (`DANETLS_TA_MASK`: PKIX-TA and DANE-TA).
pub(crate) const TA_MASK: u32 = usage_bit(USAGE_PKIX_TA) | usage_bit(USAGE_DANE_TA);
/// The usages whose records name the end entity (`DANETLS_EE_MASK`).
pub(crate) const EE_MASK: u32 = usage_bit(USAGE_PKIX_EE) | usage_bit(USAGE_DANE_EE);
/// The PKIX usages (`DANETLS_PKIX_MASK`).
pub(crate) const PKIX_MASK: u32 = usage_bit(USAGE_PKIX_TA) | usage_bit(USAGE_PKIX_EE);
/// The DANE usages (`DANETLS_DANE_MASK`).
pub(crate) const DANE_MASK: u32 = usage_bit(USAGE_DANE_TA) | usage_bit(USAGE_DANE_EE);
/// Cert(0), SPKI(1).
pub(crate) const SELECTOR_CERT: u8 = 0;
/// See [`SELECTOR_CERT`].
pub(crate) const SELECTOR_SPKI: u8 = 1;
/// See [`SELECTOR_CERT`].
const SELECTOR_LAST: u8 = 1;
/// Full(0), SHA2-256(1), SHA2-512(2).
pub(crate) const MATCHING_FULL: u8 = 0;
/// See [`MATCHING_FULL`].
const MATCHING_LAST: u8 = 2;

/// A context's matching types (`dane_ctx_st`): each type's digest (NULL: disabled) and
/// preference ordinal; empty until `SSL_CTX_dane_enable`.
#[derive(Debug, Default)]
pub(crate) struct DaneCtx {
    mds: Vec<(*const EVP_MD, u8)>,
    flags: c_ulong,
}

/// A TLSA record (`danetls_record`).
#[derive(Debug)]
pub(crate) struct Tlsa {
    pub(crate) usage: u8,
    pub(crate) selector: u8,
    pub(crate) mtype: u8,
    pub(crate) data: Vec<u8>,
    /// A DANE-TA(2) SPKI(1) Full(0) record's key (owned), or NULL.
    pub(crate) spki: *mut EVP_PKEY,
}

impl Drop for Tlsa {
    fn drop(&mut self) {
        // SAFETY: our own key, or NULL.
        unsafe { EVP_PKEY_free(self.spki) };
    }
}

/// A connection's DANE state (`ssl_dane_st`), at a stable address for `SSL_get0_dane`.
#[derive(Debug)]
pub(crate) struct Dane {
    /// The records (boxed, so a match can point at one), or `None` until `SSL_dane_enable`.
    #[expect(
        clippy::vec_box,
        reason = "a match points at its record, which an insert would otherwise move"
    )]
    trecs: Option<Vec<Box<Tlsa>>>,
    /// The Full(0) trust anchor certificates of the records (owned), or NULL.
    pub(crate) certs: *mut stack_st_X509,
    /// The usages present (`umask`).
    pub(crate) umask: u32,
    pub(crate) flags: c_ulong,
    /// The context's matching types (`dctx`), copied each time the connection's records are
    /// set up or verified, as the verifier can't take the context's lock.
    mds: Vec<(*const EVP_MD, u8)>,
    /// The certificate that matched a record (a reference), or NULL for a bare DANE-TA key.
    pub(crate) mcert: *mut X509,
    /// The record that matched, or NULL.
    pub(crate) mtlsa: *const Tlsa,
    /// The depth of the match, or -1 (`mdpth`).
    pub(crate) mdpth: c_int,
    /// The depth of a PKIX trust anchor found, or -1 (`pdpth`).
    pub(crate) pdpth: c_int,
}

impl Default for Dane {
    fn default() -> Self {
        Self {
            trecs: None,
            certs: ptr::null_mut(),
            umask: 0,
            flags: 0,
            mds: Vec::new(),
            mcert: ptr::null_mut(),
            mtlsa: ptr::null(),
            mdpth: -1,
            pdpth: -1,
        }
    }
}

impl Drop for Dane {
    fn drop(&mut self) {
        // SAFETY: our own certificates, or NULL.
        unsafe { OSSL_STACK_OF_X509_free(self.certs) };
        // SAFETY: our reference, or NULL.
        unsafe { X509_free(self.mcert) };
    }
}

impl Dane {
    /// A new connection's state: the context's flags (`SSL_new`).
    pub(crate) fn for_ssl(ctx: &DaneCtx) -> Box<Self> {
        let mut d = Box::<Self>::default();
        d.flags = ctx.flags;
        d
    }

    /// `DANETLS_ENABLED`: whether the connection has records to verify against.
    pub(crate) fn enabled(&self) -> bool {
        self.trecs.as_ref().is_some_and(|t| !t.is_empty())
    }

    /// The records, in matching order.
    pub(crate) fn records(&self) -> impl Iterator<Item = &Tlsa> {
        self.trecs.iter().flatten().map(|t| &**t)
    }

    /// The digest of matching type `mtype` (`dctx->mdevp`), or NULL (Full, or disabled).
    pub(crate) fn md(&self, mtype: u8) -> *const EVP_MD {
        self.mds
            .get(usize::from(mtype))
            .map_or(ptr::null(), |&(md, _)| md)
    }

    /// The preference ordinal of matching type `mtype` (`dctx->mdord`).
    pub(crate) fn ord(&self, mtype: u8) -> u8 {
        self.mds.get(usize::from(mtype)).map_or(0, |&(_, o)| o)
    }

    /// Takes the context's matching types (`dctx`), for the verifier.
    pub(crate) fn refresh(&mut self, ctx: &DaneCtx) {
        self.mds.clone_from(&ctx.mds);
    }

    /// The record that matched, if it's still one of the connection's.
    fn matched(&self) -> Option<&Tlsa> {
        self.records().find(|t| ptr::eq(*t, self.mtlsa))
    }

    /// Clears the result of a verification (`dane_reset`), handing back the certificate's
    /// reference for the caller to free with no lock held.
    #[must_use]
    pub(crate) fn reset(&mut self) -> *mut X509 {
        self.mtlsa = ptr::null();
        self.mdpth = -1;
        self.pdpth = -1;
        core::mem::replace(&mut self.mcert, ptr::null_mut())
    }
}

/// The digest of a matching type, if enabled (`tlsa_md_get`).
fn md_of(d: &DaneCtx, mtype: u8) -> *const EVP_MD {
    d.mds
        .get(usize::from(mtype))
        .map_or(ptr::null(), |&(md, _)| md)
}

/// The preference ordinal of a matching type.
fn ord_of(d: &DaneCtx, mtype: u8) -> u8 {
    d.mds.get(usize::from(mtype)).map_or(0, |&(_, o)| o)
}

/// `dane_ctx_enable`: the default matching types.
fn ctx_enable(d: &mut DaneCtx) {
    if !d.mds.is_empty() {
        return;
    }
    let mut mds = vec![(ptr::null::<EVP_MD>(), 0u8); usize::from(MATCHING_LAST) + 1];
    for (slot, nid, ord) in [(1usize, NID_sha256, 1u8), (2, NID_sha512, 2)] {
        // SAFETY: no preconditions (a static name).
        let name = unsafe { OBJ_nid2sn(nid) };
        // SAFETY: the name, for the legacy lookup (`EVP_get_digestbynid`).
        let md = unsafe { EVP_get_digestbyname(name) };
        if let Some(e) = mds.get_mut(slot)
            && !md.is_null()
        {
            *e = (md, ord);
        }
    }
    d.mds = mds;
}

/// `dane_mtype_set`.
fn mtype_set(d: &mut DaneCtx, md: *const EVP_MD, mtype: u8, ord: u8) -> c_int {
    if mtype == MATCHING_FULL && !md.is_null() {
        err::raise(
            ERR_LIB_SSL,
            SSL_R_DANE_CANNOT_OVERRIDE_MTYPE_FULL,
            "dane_mtype_set",
        );
        return 0;
    }
    let i = usize::from(mtype);
    if i >= d.mds.len() {
        d.mds.resize(i + 1, (ptr::null(), 0));
    }
    if let Some(e) = d.mds.get_mut(i) {
        *e = (md, if md.is_null() { 0 } else { ord });
    }
    1
}

/// `dane_tlsa_add`: 1, 0 for a bad record, -1 for DANE not enabled or no memory.
///
/// # Safety
/// `data` is NULL or points to `dlen` octets.
unsafe fn tlsa_add(
    dane: &mut Dane,
    dctx: &DaneCtx,
    usage: u8,
    selector: u8,
    mtype: u8,
    data: *const u8,
    dlen: usize,
) -> c_int {
    const F: &str = "dane_tlsa_add";
    if dane.trecs.is_none() {
        err::raise(ERR_LIB_SSL, SSL_R_DANE_NOT_ENABLED, F);
        return -1;
    }
    let Ok(ilen) = c_int::try_from(dlen) else {
        err::raise(ERR_LIB_SSL, SSL_R_DANE_TLSA_BAD_DATA_LENGTH, F);
        return 0;
    };
    if usage > USAGE_LAST {
        err::raise(ERR_LIB_SSL, SSL_R_DANE_TLSA_BAD_CERTIFICATE_USAGE, F);
        return 0;
    }
    if selector > SELECTOR_LAST {
        err::raise(ERR_LIB_SSL, SSL_R_DANE_TLSA_BAD_SELECTOR, F);
        return 0;
    }
    if mtype != MATCHING_FULL {
        let md = md_of(dctx, mtype);
        if md.is_null() {
            err::raise(ERR_LIB_SSL, SSL_R_DANE_TLSA_BAD_MATCHING_TYPE, F);
            return 0;
        }
        // SAFETY: a digest the context was given.
        let size = unsafe { EVP_MD_get_size(md) };
        if usize::try_from(size).ok().filter(|&n| n > 0) != Some(dlen) {
            err::raise(ERR_LIB_SSL, SSL_R_DANE_TLSA_BAD_DIGEST_LENGTH, F);
            return 0;
        }
    }
    if data.is_null() {
        err::raise(ERR_LIB_SSL, SSL_R_DANE_TLSA_NULL_DATA, F);
        return 0;
    }
    // SAFETY: the caller's octets.
    let bytes = unsafe { core::slice::from_raw_parts(data, dlen) };
    let mut t = Box::new(Tlsa {
        usage,
        selector,
        mtype,
        data: bytes.to_vec(),
        spki: ptr::null_mut(),
    });
    if mtype == MATCHING_FULL {
        let len = c_long::from(ilen);
        let mut p = data;
        if selector == SELECTOR_CERT {
            // SAFETY: the octets, and our cursor.
            let cert = unsafe { d2i_X509(ptr::null_mut(), &raw mut p, len) };
            let used = p.addr().wrapping_sub(data.addr());
            // SAFETY: the certificate, or NULL.
            if cert.is_null() || used != dlen || unsafe { X509_get0_pubkey(cert) }.is_null() {
                // SAFETY: as above.
                unsafe { X509_free(cert) };
                err::raise(ERR_LIB_SSL, SSL_R_DANE_TLSA_BAD_CERTIFICATE, F);
                return 0;
            }
            if usage_bit(usage) & TA_MASK == 0 {
                // SAFETY: decoded above, not kept.
                unsafe { X509_free(cert) };
            } else if !push_cert(dane, cert) {
                err::raise(ERR_LIB_SSL, ERR_R_CRYPTO_LIB, F);
                return -1;
            }
        } else if selector == SELECTOR_SPKI {
            // SAFETY: the octets, and our cursor.
            let pkey = unsafe { d2i_PUBKEY(ptr::null_mut(), &raw mut p, len) };
            let used = p.addr().wrapping_sub(data.addr());
            if pkey.is_null() || used != dlen {
                // SAFETY: the key, or NULL.
                unsafe { EVP_PKEY_free(pkey) };
                err::raise(ERR_LIB_SSL, SSL_R_DANE_TLSA_BAD_PUBLIC_KEY, F);
                return 0;
            }
            if usage == USAGE_DANE_TA {
                t.spki = pkey;
            } else {
                // SAFETY: decoded above, not kept.
                unsafe { EVP_PKEY_free(pkey) };
            }
        }
    }
    let Some(trecs) = dane.trecs.as_mut() else {
        return -1;
    };
    // DANE-EE first (descending usage), then descending selector and matching ordinal.
    let at = trecs
        .iter()
        .position(|r| {
            if r.usage != usage {
                return r.usage < usage;
            }
            if r.selector != selector {
                return r.selector < selector;
            }
            ord_of(dctx, r.mtype) <= ord_of(dctx, mtype)
        })
        .unwrap_or(trecs.len());
    trecs.insert(at, t);
    dane.umask |= usage_bit(usage);
    dane.refresh(dctx);
    1
}

/// Keeps a trust anchor certificate (taking it); `false` (having freed it) on failure.
fn push_cert(dane: &mut Dane, cert: *mut X509) -> bool {
    if dane.certs.is_null() {
        // SAFETY: no preconditions.
        dane.certs = unsafe { OPENSSL_sk_new_null() }.cast();
    }
    // SAFETY: our list, or NULL (which fails); the certificate, taken.
    if dane.certs.is_null() || unsafe { OPENSSL_sk_push(dane.certs.cast(), cert.cast()) } == 0 {
        // SAFETY: not taken.
        unsafe { X509_free(cert) };
        return false;
    }
    true
}

ffi_export! {
    /// Enables DANE for the context's connections, with the SHA2-256 and SHA2-512 matching
    /// types: 1.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_dane_enable(c: *mut SSL_CTX) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx(c) }) else { return 0 };
        ctx_enable(&mut x.state().lists.dane_ctx);
        1
    }
}

ffi_export! {
    /// Sets matching type `mtype`'s digest (NULL: disabled) and preference ordinal: 1, or 0
    /// (Full(0) can't take a digest).
    ///
    /// # Safety
    /// `c` is NULL or a live context; `md` NULL or a digest that outlives it.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_dane_mtype_set(c: *mut SSL_CTX, md: *const EVP_MD, mtype: u8, ord: u8) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx(c) }) else { return 0 };
        mtype_set(&mut x.state().lists.dane_ctx, md, mtype, ord)
    }
}

ffi_export! {
    /// Adds DANE flags (`DANE_FLAG_*`) for the context's new connections; returns the old ones.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_dane_set_flags(c: *mut SSL_CTX, flags: c_ulong) -> c_ulong
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx(c) }) else { return 0 };
        let d = &mut x.state().lists.dane_ctx;
        let old = d.flags;
        d.flags |= flags;
        old
    }
}

ffi_export! {
    /// Clears DANE flags for the context's new connections; returns the old ones.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_dane_clear_flags(c: *mut SSL_CTX, flags: c_ulong) -> c_ulong
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx(c) }) else { return 0 };
        let d = &mut x.state().lists.dane_ctx;
        let old = d.flags;
        d.flags &= !flags;
        old
    }
}

ffi_export! {
    /// Enables DANE on the connection for `basedomain` (the SNI name, unless one is set, and
    /// the name to check): 1; 0 when the context isn't DANE-enabled or it already is; -1 when
    /// the name can't be set.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `basedomain` NULL or a C string.
    pub unsafe extern "C" fn rustyssl_private_SSL_dane_enable(s: *mut SSL, basedomain: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        const F: &str = "SSL_dane_enable";
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let (ctx_enabled, already, has_host, param) = {
            let mut st = x.state();
            // SAFETY: the connection holds a reference to its context.
            let cx = unsafe { ctx_of(&st) };
            let enabled = cx.is_some_and(|c| {
                let cs = c.state();
                st.lists.dane.refresh(&cs.lists.dane_ctx);
                cs.lists.dane_ctx.mds.len() > 1
            });
            (enabled, st.lists.dane.trecs.is_some(), st.hostname.is_some(), x.param)
        };
        if !ctx_enabled {
            err::raise(ERR_LIB_SSL, SSL_R_CONTEXT_NOT_DANE_ENABLED, F);
            return 0;
        }
        if already {
            err::raise(ERR_LIB_SSL, SSL_R_DANE_ALREADY_ENABLED, F);
            return 0;
        }
        let host_type = c_long::from(TLSEXT_NAMETYPE_host_name);
        // SAFETY: the live connection and the caller's name (`SSL_set_tlsext_host_name`).
        if !has_host && unsafe { rustyssl_private_SSL_ctrl(s, SSL_CTRL_SET_TLSEXT_HOSTNAME, host_type, basedomain.cast_mut().cast::<c_void>()) } == 0 {
            err::raise(ERR_LIB_SSL, SSL_R_ERROR_SETTING_TLSA_BASE_DOMAIN, F);
            return -1;
        }
        // SAFETY: the connection's parameters and the caller's name.
        if unsafe { X509_VERIFY_PARAM_set1_host(param, basedomain, 0) } == 0 {
            err::raise(ERR_LIB_SSL, SSL_R_ERROR_SETTING_TLSA_BASE_DOMAIN, F);
            return -1;
        }
        let old = {
            let mut st = x.state();
            st.lists.dane.trecs = Some(Vec::new());
            st.lists.dane.reset()
        };
        // SAFETY: the previous match's reference, or NULL, freed with no lock held.
        unsafe { X509_free(old) };
        1
    }
}

ffi_export! {
    /// Adds DANE flags to the connection; returns the old ones.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_dane_set_flags(s: *mut SSL, flags: c_ulong) -> c_ulong
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let d = &mut x.state().lists.dane;
        let old = d.flags;
        d.flags |= flags;
        old
    }
}

ffi_export! {
    /// Clears DANE flags of the connection; returns the old ones.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_dane_clear_flags(s: *mut SSL, flags: c_ulong) -> c_ulong
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let d = &mut x.state().lists.dane;
        let old = d.flags;
        d.flags &= !flags;
        old
    }
}

ffi_export! {
    /// Adds a TLSA record (usage, selector, matching type, data): 1; 0 for a malformed record;
    /// -1 when DANE isn't enabled on the connection.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `data` NULL or `dlen` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_dane_tlsa_add(s: *mut SSL, usage: u8, selector: u8, mtype: u8, data: *const u8, dlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let mut st = x.state();
        // SAFETY: the connection holds a reference to its context.
        let Some(cx) = (unsafe { ctx_of(&st) }) else { return 0 };
        // The context's matching types, read under its lock (taken after the connection's,
        // as everywhere).
        let cs = cx.state();
        // SAFETY: the caller's octets.
        unsafe { tlsa_add(&mut st.lists.dane, &cs.lists.dane_ctx, usage, selector, mtype, data, dlen) }
    }
}

ffi_export! {
    /// The connection's DANE state, for `X509_STORE_CTX_set0_dane`.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_dane(s: *mut SSL) -> *mut SSL_DANE
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return ptr::null_mut() };
        let mut st = x.state();
        // The context's matching types, for a verification the application runs with it.
        // SAFETY: the connection holds a reference to its context.
        if let Some(cx) = unsafe { ctx_of(&st) } {
            st.lists.dane.refresh(&cx.state().lists.dane_ctx);
        }
        // The state is boxed: its address is stable for the connection's lifetime.
        ptr::from_mut::<Dane>(&mut st.lists.dane).cast()
    }
}

/// The verification's match, if DANE is on and the peer verified (`SSL_get0_dane_authority`
/// and `SSL_get0_dane_tlsa`): its depth, and what `f` reads of the matching record and
/// certificate (with the connection's lock held: `f` runs no C).
fn with_match<T: Default>(
    x: &super::conn::Ssl,
    f: impl FnOnce(&Dane, Option<&Tlsa>) -> T,
) -> (c_int, T) {
    let st = x.state();
    let d = &st.lists.dane;
    if !d.enabled() || st.verify_result != c_long::from(X509_V_OK) {
        return (-1, T::default());
    }
    (d.mdpth, f(d, d.matched()))
}

/// Writes `v` through `p` unless it's NULL.
///
/// # Safety
/// `p` is NULL or writable.
unsafe fn put<T>(p: *mut T, v: T) {
    // SAFETY: the caller's guarantee.
    if let Some(r) = unsafe { p.as_mut() } {
        *r = v;
    }
}

ffi_export! {
    /// The depth of the certificate that matched a TLSA record, or -1 for no match (DANE off,
    /// or verification failed or hasn't run); with a match, the certificate (`mcert`), or the
    /// DANE-TA record's bare key when no certificate matched (`mspki`; NULL otherwise).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `mcert` and `mspki` NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_dane_authority(s: *mut SSL, mcert: *mut *mut X509, mspki: *mut *mut EVP_PKEY) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return -1 };
        let (depth, found) = with_match(x, |d, t| {
            t.map(|t| (d.mcert, if d.mcert.is_null() { t.spki } else { ptr::null_mut() }))
        });
        if let Some((cert, spki)) = found {
            // SAFETY: the caller's pointers.
            unsafe { put(mcert, cert) };
            // SAFETY: as above.
            unsafe { put(mspki, spki) };
        }
        depth
    }
}

ffi_export! {
    /// The TLSA record that matched (its fields, and its data, valid while the connection's
    /// records are) and its depth, or -1 for no match (as for the authority).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; the out-arguments NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_dane_tlsa(s: *mut SSL, usage: *mut u8, selector: *mut u8, mtype: *mut u8, data: *mut *const u8, dlen: *mut usize) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return -1 };
        let (depth, found) = with_match(x, |_, t| {
            t.map(|t| (t.usage, t.selector, t.mtype, t.data.as_ptr(), t.data.len()))
        });
        if let Some((u, sel, m, p, n)) = found {
            // SAFETY: the caller's pointers.
            unsafe { put(usage, u) };
            // SAFETY: as above.
            unsafe { put(selector, sel) };
            // SAFETY: as above.
            unsafe { put(mtype, m) };
            // SAFETY: as above.
            unsafe { put(data, p) };
            // SAFETY: as above.
            unsafe { put(dlen, n) };
        }
        depth
    }
}
