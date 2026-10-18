//! DANE verification (`x509_vfy.c`'s `dane_*`, RFC 7671): the peer's certificates matched
//! against a connection's TLSA records (libssl's state, given by `X509_STORE_CTX_set0_dane`).
//!
//! A DANE-EE(3) match of the leaf authenticates it outright (no chain, no expiry; the name is
//! checked unless `DANE_FLAG_NO_DANE_EE_NAMECHECKS`). Otherwise the chain is built as usual
//! with the records consulted on the way (`verify.rs`): a DANE-TA(2) match of a certificate
//! from the wire (or a bare DANE-TA key that signed the top of the chain) makes it the trust
//! anchor, and a PKIX-TA(0)/PKIX-EE(1) match is needed besides an ordinary PKIX trust anchor.
//! The match's record, certificate, and depth are left in the state (`mtlsa`, `mcert`,
//! `mdpth`), for `SSL_get0_dane_authority` and `SSL_get0_dane_tlsa`.
//!
//! The state is reached through the context's pointer with no lock (as the verification
//! callbacks may read it through the connection), so each access is brief and no C runs while
//! it lasts: the records are copied out before they're matched.

use core::ffi::{c_int, c_uchar, c_uint, c_ulong};
use core::ptr;

use rustyssl_abi::{
    DANE_FLAG_NO_DANE_EE_NAMECHECKS, ERR_LIB_X509, ERR_R_ASN1_LIB, EVP_MAX_MD_SIZE, EVP_MD,
    EVP_PKEY, X509, X509_R_BAD_SELECTOR, X509_STORE_CTX, X509_TRUST_TRUSTED, X509_TRUST_UNTRUSTED,
    X509_V_ERR_DANE_NO_MATCH, X509_V_ERR_OUT_OF_MEM, X509_V_ERR_UNSPECIFIED, X509_V_OK,
    stack_st_X509,
};

use super::cert::{
    X509_chain_check_suiteb, X509_free, X509_get_X509_PUBKEY, X509_get_pubkey_parameters,
    X509_up_ref, X509_verify, i2d_X509,
};
use super::ctx::{Ctx, ctx_of, verify_cb_cert};
use super::pubkey::{i2d_PUBKEY, i2d_X509_PUBKEY};
use crate::err;
use crate::evp::md_ctx::EVP_Digest;
use crate::ssl::dane::{
    DANE_MASK, Dane, EE_MASK, MATCHING_FULL, PKIX_MASK, SELECTOR_CERT, SELECTOR_SPKI, TA_MASK,
    Tlsa, USAGE_DANE_EE, USAGE_DANE_TA, usage_bit,
};
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_pop, OPENSSL_sk_value};

/// The context's DANE state, if it has one (not the context's own memory: libssl's).
#[expect(
    clippy::mut_from_ref,
    reason = "the state is the connection's, not the context's"
)]
fn dane(c: &Ctx) -> Option<&mut Dane> {
    // SAFETY: a context's DANE state is NULL or libssl's live state
    // (`X509_STORE_CTX_set0_dane`), reached only briefly, with no C running meanwhile.
    unsafe { c.dane.cast::<Dane>().as_mut() }
}

/// `DANETLS_ENABLED`: the context has a DANE state with records.
pub(super) fn enabled(c: &Ctx) -> bool {
    dane(c).is_some_and(|d| d.enabled())
}

/// The usages of the state's records (`umask`; 0 without a state), for `DANETLS_HAS_*`.
pub(super) fn umask(c: &Ctx) -> u32 {
    dane(c).map_or(0, |d| d.umask)
}

/// `DANETLS_HAS_PKIX`.
pub(super) fn has_pkix(c: &Ctx) -> bool {
    umask(c) & PKIX_MASK != 0
}

/// `DANETLS_HAS_DANE`.
pub(super) fn has_dane(c: &Ctx) -> bool {
    umask(c) & DANE_MASK != 0
}

/// `DANETLS_HAS_TA`.
fn has_ta(c: &Ctx) -> bool {
    umask(c) & TA_MASK != 0
}

/// `DANETLS_HAS_DANE_TA`.
pub(super) fn has_dane_ta(c: &Ctx) -> bool {
    umask(c) & usage_bit(USAGE_DANE_TA) != 0
}

/// The depth of a PKIX trust anchor found so far (`pdpth`), or -1.
pub(super) fn pdpth(c: &Ctx) -> c_int {
    dane(c).map_or(-1, |d| d.pdpth)
}

/// The Full(0) trust anchor certificates of the records (`dane->certs`), or NULL.
pub(super) fn certs(c: &Ctx) -> *mut stack_st_X509 {
    dane(c)
        .filter(|d| d.enabled())
        .map_or(ptr::null_mut(), |d| d.certs)
}

/// A record, copied out of the state with what the matching needs.
struct Rec {
    usage: u8,
    selector: u8,
    mtype: u8,
    data: Vec<u8>,
    spki: *mut EVP_PKEY,
    /// The matching type's digest (NULL for Full) and preference ordinal.
    md: *const EVP_MD,
    ord: u8,
    /// The record in the state, for `mtlsa`.
    at: *const Tlsa,
}

/// The state's records, in order.
fn records(d: &Dane) -> Vec<Rec> {
    d.records()
        .map(|t| Rec {
            usage: t.usage,
            selector: t.selector,
            mtype: t.mtype,
            data: t.data.clone(),
            spki: t.spki,
            md: d.md(t.mtype),
            ord: d.ord(t.mtype),
            at: ptr::from_ref(t),
        })
        .collect()
}

/// Records a match (`mcert`, `mdpth`, `mtlsa`), freeing the previous certificate's reference.
fn set_match(c: &Ctx, cert: *mut X509, depth: c_int, at: *const Tlsa) {
    let old = dane(c).map_or(ptr::null_mut(), |d| {
        d.mdpth = depth;
        d.mtlsa = at;
        core::mem::replace(&mut d.mcert, cert)
    });
    // SAFETY: the previous match's reference, or NULL.
    unsafe { X509_free(old) };
}

/// `dane_reset`.
fn reset(c: &Ctx) {
    let old = dane(c).map_or(ptr::null_mut(), Dane::reset);
    // SAFETY: the previous match's reference, or NULL.
    unsafe { X509_free(old) };
}

/// An encoding by an `i2d` function: its length first, then into our buffer.
fn encode(i2d: impl Fn(*mut *mut c_uchar) -> c_int) -> Option<Vec<u8>> {
    let len = usize::try_from(i2d(ptr::null_mut())).ok()?;
    let mut buf = vec![0u8; len];
    let mut p = buf.as_mut_ptr();
    let n = usize::try_from(i2d(&raw mut p)).ok()?;
    buf.truncate(n);
    Some(buf)
}

/// `dane_i2d`: the certificate's DER (Cert(0)) or its key's (SPKI(1)).
fn dane_i2d(cert: *mut X509, selector: u8) -> Option<Vec<u8>> {
    let der = match selector {
        // SAFETY: a live certificate; the output is NULL or our buffer.
        SELECTOR_CERT => encode(|pp| unsafe { i2d_X509(cert, pp) }),
        SELECTOR_SPKI => {
            // SAFETY: a live certificate.
            let key = unsafe { X509_get_X509_PUBKEY(cert) };
            // SAFETY: its key; the output is NULL or our buffer.
            encode(|pp| unsafe { i2d_X509_PUBKEY(key, pp) })
        }
        _ => {
            err::raise(ERR_LIB_X509, X509_R_BAD_SELECTOR, "dane_i2d");
            return None;
        }
    };
    if der.is_none() {
        err::raise(ERR_LIB_X509, ERR_R_ASN1_LIB, "dane_i2d");
    }
    der
}

/// The octets as the record's matching type compares them: themselves (Full), or their digest.
fn compared(der: &[u8], md: *const EVP_MD) -> Option<Vec<u8>> {
    if md.is_null() {
        return Some(der.to_vec());
    }
    let mut buf = vec![0u8; usize::try_from(EVP_MAX_MD_SIZE).ok()?];
    let mut len: c_uint = 0;
    // SAFETY: the octets; our buffer of the largest digest; the record's digest.
    let ok = unsafe {
        EVP_Digest(
            der.as_ptr().cast(),
            der.len(),
            buf.as_mut_ptr(),
            &raw mut len,
            md,
            ptr::null_mut(),
        )
    };
    let n = usize::try_from(len).ok()?;
    (ok != 0)
        .then(|| buf.get(..n).map(<[u8]>::to_vec))
        .flatten()
}

/// `dane_match_cert`: whether `cert` at `depth` matches a record: 1 for a DANE-?? record
/// (dispositive), 0 otherwise (a PKIX-?? match is recorded, as the chain still needs a PKIX
/// trust anchor), -1 on failure.
pub(super) fn match_cert(c: &Ctx, cert: *mut X509, depth: c_int) -> c_int {
    let Some((recs, umask, mdpth)) = dane(c).map(|d| (records(d), d.umask, d.mdpth)) else {
        return 0;
    };
    let mut mask = if depth == 0 { EE_MASK } else { TA_MASK };
    // The trust store doesn't count for DANE-TA(2).
    if depth >= c.num_untrusted {
        mask &= PKIX_MASK;
    }
    // After a PKIX-?? match, only the chain remains to build.
    if mdpth >= 0 {
        mask &= !PKIX_MASK;
    }
    let recs: &[Rec] = if umask & mask != 0 { &recs } else { &[] };
    // DANE-EE(3) records come first; for each usage and selector, the digests of the highest
    // ordinal (and Full) are tried, the others ignored (digest agility, RFC 7671 section 9).
    let (mut usage, mut selector, mut mtype) = (None, None, None);
    let mut ordinal = 0u8;
    let mut der = Vec::new();
    let mut cmp = Vec::new();
    let mut matched = 0;
    for t in recs {
        if usage_bit(t.usage) & mask == 0 {
            continue;
        }
        if usage != Some(t.usage) {
            usage = Some(t.usage);
            mtype = None;
            ordinal = t.ord;
        }
        if selector != Some(t.selector) {
            selector = Some(t.selector);
            let Some(d) = dane_i2d(cert, t.selector) else {
                return -1;
            };
            der = d;
            mtype = None;
            ordinal = t.ord;
        } else if t.mtype != MATCHING_FULL && t.ord < ordinal {
            continue;
        }
        if mtype != Some(t.mtype) {
            mtype = Some(t.mtype);
            let Some(v) = compared(&der, t.md) else {
                matched = -1;
                break;
            };
            cmp = v;
        }
        if cmp == t.data {
            if usage_bit(t.usage) & DANE_MASK != 0 {
                matched = 1;
            }
            if matched != 0 || mdpth < 0 {
                // SAFETY: a live certificate.
                if unsafe { X509_up_ref(cert) } == 0 {
                    return -1;
                }
                set_match(c, cert, depth, t.at);
            }
            break;
        }
    }
    matched
}

/// `check_dane_issuer`: whether the chain's certificate at `depth` (from the wire) matches a
/// DANE-TA(2) record, making it the trust anchor.
pub(super) fn check_issuer(c: &mut Ctx, depth: c_int) -> c_int {
    if !has_ta(c) || depth == 0 {
        return X509_TRUST_UNTRUSTED;
    }
    // SAFETY: the context's chain.
    let cert: *mut X509 = unsafe { OPENSSL_sk_value(c.chain.cast(), depth) }.cast();
    let matched = if cert.is_null() {
        0
    } else {
        match_cert(c, cert, depth)
    };
    if matched < 0 {
        return matched;
    }
    if matched > 0 {
        c.num_untrusted = depth - 1;
        return X509_TRUST_TRUSTED;
    }
    X509_TRUST_UNTRUSTED
}

/// `check_dane_pkeys`: whether a DANE-TA(2) SPKI(1) Full(0) record's bare key signed the top
/// untrusted certificate, making that key the trust anchor (the chain above is dropped).
pub(super) fn check_pkeys(c: &mut Ctx) -> c_int {
    let Some(recs) = dane(c).map(|d| records(d)) else {
        return X509_TRUST_UNTRUSTED;
    };
    let num = c.num_untrusted;
    // SAFETY: the context's chain.
    let cert: *mut X509 = unsafe { OPENSSL_sk_value(c.chain.cast(), num - 1) }.cast();
    for t in &recs {
        if t.usage != USAGE_DANE_TA
            || t.selector != SELECTOR_SPKI
            || t.mtype != MATCHING_FULL
            || t.spki.is_null()
            || cert.is_null()
            // SAFETY: a certificate of the chain; the record's key.
            || unsafe { X509_verify(cert, t.spki) } <= 0
        {
            continue;
        }
        // Any PKIX-?? match that didn't make a whole chain goes.
        set_match(c, ptr::null_mut(), num - 1, t.at);
        c.bare_ta_signed = 1;
        // SAFETY: the context's chain.
        let mut n = unsafe { OPENSSL_sk_num(c.chain.cast()) };
        while n > c.num_untrusted {
            // SAFETY: as above.
            let last = unsafe { OPENSSL_sk_pop(c.chain.cast()) };
            // SAFETY: its last certificate, whose reference it held.
            unsafe { X509_free(last.cast()) };
            n -= 1;
        }
        return X509_TRUST_TRUSTED;
    }
    X509_TRUST_UNTRUSTED
}

/// `check_trust`'s end with DANE: a PKIX trust anchor at `num_untrusted` is recorded
/// (`pdpth`), and suffices only with a TLSA match.
pub(super) fn pkix_trusted(c: &Ctx, num_untrusted: c_int) -> c_int {
    let Some(d) = dane(c).filter(|d| d.enabled()) else {
        return X509_TRUST_TRUSTED;
    };
    if d.pdpth < 0 {
        d.pdpth = num_untrusted;
    }
    if d.mdpth >= 0 {
        X509_TRUST_TRUSTED
    } else {
        X509_TRUST_UNTRUSTED
    }
}

/// `build_chain`'s pruning for an alternate chain: matches above the shorter chain go.
pub(super) fn prune(c: &Ctx) {
    let num_untrusted = c.num_untrusted;
    let old = dane(c)
        .filter(|d| d.enabled())
        .map_or(ptr::null_mut(), |d| {
            if d.pdpth >= num_untrusted {
                d.pdpth = -1;
            }
            if d.mdpth >= num_untrusted {
                d.mdpth = -1;
                core::mem::replace(&mut d.mcert, ptr::null_mut())
            } else {
                ptr::null_mut()
            }
        });
    // SAFETY: the dropped match's reference, or NULL.
    unsafe { X509_free(old) };
}

/// `check_leaf_suiteb`: whether to go on after the leaf's Suite B check.
///
/// # Safety
/// `ctx` is a live context; `cert` its leaf.
unsafe fn leaf_suiteb_ok(ctx: *mut X509_STORE_CTX, cert: *mut X509) -> bool {
    // SAFETY: the caller's guarantee.
    let flags = unsafe { ctx_of(ctx) }.map_or(0, |c| super::verify::flags_of(c));
    // SAFETY: the leaf alone.
    let e = unsafe { X509_chain_check_suiteb(ptr::null_mut(), cert, ptr::null_mut(), flags) };
    // SAFETY: the caller's guarantee.
    e == X509_V_OK || unsafe { verify_cb_cert(ctx, cert, 0, e) } != 0
}

/// `dane_verify`: the leaf against the DANE-EE(3) and PKIX-EE(1) records, then (unless that
/// settled it) the chain, with the TA records matched as it's built.
///
/// # Safety
/// `ctx` is a live context with its leaf in its chain and a DANE state with records.
pub(super) unsafe fn verify(ctx: *mut X509_STORE_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return -1;
    };
    let cert = c.cert;
    reset(c);
    let matched = match_cert(c, cert, 0);
    let done = matched != 0 || (!has_ta(c) && dane(c).is_none_or(|d| d.mdpth < 0));
    // SAFETY: the context's chain.
    if done && unsafe { X509_get_pubkey_parameters(ptr::null_mut(), c.chain) } == 0 {
        return -1;
    }
    if matched > 0 {
        let flags = dane(c).map_or(0, |d| d.flags);
        let no_names = c_ulong::try_from(DANE_FLAG_NO_DANE_EE_NAMECHECKS).unwrap_or(0);
        // SAFETY: the caller's guarantee.
        if !unsafe { leaf_suiteb_ok(ctx, cert) } {
            return 0;
        }
        // SAFETY: as above.
        if flags & no_names == 0 && unsafe { super::verify::check_id(ctx) } == 0 {
            return 0;
        }
        // No chain to check: the depth 0 success callback.
        // SAFETY: as above.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            return -1;
        };
        c.error_depth = 0;
        c.current_cert = cert;
        let cb = c.verify_cb;
        // SAFETY: the context's callback, with no reference into it held.
        return cb.map_or(0, |f| unsafe { f(1, ctx) });
    }
    if matched < 0 {
        c.error_depth = 0;
        c.current_cert = cert;
        c.error = X509_V_ERR_OUT_OF_MEM;
        return -1;
    }
    if done {
        // No TA record could make it: fail early.
        // SAFETY: the caller's guarantee.
        if !unsafe { leaf_suiteb_ok(ctx, cert) } {
            return 0;
        }
        // SAFETY: as above.
        return unsafe { verify_cb_cert(ctx, cert, 0, X509_V_ERR_DANE_NO_MATCH) };
    }
    // SAFETY: as above.
    unsafe { super::verify::verify_chain(ctx) }
}

/// `dane_verify_rpk`'s matching: the raw public key against the DANE-EE(3) SPKI(1) records,
/// setting the context's error (`X509_V_OK`, or `X509_V_ERR_DANE_NO_MATCH`); `false` on
/// failure (`X509_V_ERR_UNSPECIFIED`).
pub(super) fn match_rpk(c: &mut Ctx) -> bool {
    reset(c);
    let recs = dane(c).map(|d| records(d)).unwrap_or_default();
    let rpk = c.rpk;
    // SAFETY: the context's key; the output is NULL or our buffer.
    let der = encode(|pp| unsafe { i2d_PUBKEY(rpk, pp) }).filter(|d| !d.is_empty());
    let matched = der.and_then(|der| {
        let mut mtype = MATCHING_FULL;
        let mut cmp = der.clone();
        for t in &recs {
            if t.usage != USAGE_DANE_EE || t.selector != SELECTOR_SPKI {
                continue;
            }
            if t.mtype != mtype {
                mtype = t.mtype;
                cmp = compared(&der, t.md)?;
            }
            if cmp == t.data {
                if let Some(d) = dane(c) {
                    d.mdpth = 0;
                    d.mtlsa = t.at;
                }
                return Some(true);
            }
        }
        Some(false)
    });
    c.error_depth = 0;
    match matched {
        None => {
            c.error = X509_V_ERR_UNSPECIFIED;
            false
        }
        Some(m) => {
            c.error = if m {
                X509_V_OK
            } else {
                X509_V_ERR_DANE_NO_MATCH
            };
            true
        }
    }
}
