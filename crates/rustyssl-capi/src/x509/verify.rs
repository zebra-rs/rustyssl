//! Verification (`x509_vfy.c`): `X509_verify_cert`, `X509_STORE_CTX_verify`, and
//! `X509_build_chain`. The chain is built from the certificate up through the untrusted
//! certificates and the store (trusted issuers first or last, then alternate chains, partial
//! chains if asked for), then checked: trust, the extensions and purposes, path and proxy path
//! lengths, the security level of keys and signatures, the identities, revocation (`revoke.rs`),
//! Suite B, the signatures and validity times, name constraints, RFC 3779 resources,
//! and policies (`pcy.rs`). Each failure goes to the verification callback, which may accept it,
//! with the error, its depth, and its certificate set, as OpenSSL's.
//!
//! DANE comes with libssl's: verifying with a DANE state aborts until then.

use core::ffi::{c_char, c_int, c_long, c_ulong};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_X509, ERR_R_CRYPTO_LIB, ERR_R_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER,
    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, ERR_R_X509_LIB, EVP_PKEY, EVP_PKEY_EC, EXFLAG_AKID_CRITICAL,
    EXFLAG_BCONS, EXFLAG_BCONS_CRITICAL, EXFLAG_CA, EXFLAG_CRITICAL, EXFLAG_KUSAGE, EXFLAG_PROXY,
    EXFLAG_SAN_CRITICAL, EXFLAG_SI, EXFLAG_SKID_CRITICAL, EXFLAG_SS, GEN_DNS, GENERAL_NAME,
    KU_CRL_SIGN, KU_KEY_CERT_SIGN, NID_commonName, OSSL_LIB_CTX,
    OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, X509, X509_ADD_FLAG_DEFAULT,
    X509_ADD_FLAG_NO_SS, X509_ADD_FLAG_UP_REF, X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT,
    X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, X509_PURPOSE_CRL_SIGN, X509_PURPOSE_MIN,
    X509_R_NO_CERT_SET_FOR_US_TO_VERIFY, X509_STORE, X509_STORE_CTX, X509_TRUST_NO_SS_COMPAT,
    X509_TRUST_REJECTED, X509_TRUST_TRUSTED, X509_TRUST_UNTRUSTED,
    X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL, X509_V_ERR_CA_BCONS_NOT_CRITICAL,
    X509_V_ERR_CA_CERT_MISSING_KEY_USAGE, X509_V_ERR_CA_KEY_TOO_SMALL, X509_V_ERR_CA_MD_TOO_WEAK,
    X509_V_ERR_CERT_CHAIN_TOO_LONG, X509_V_ERR_CERT_HAS_EXPIRED, X509_V_ERR_CERT_NOT_YET_VALID,
    X509_V_ERR_CERT_REJECTED, X509_V_ERR_CERT_SIGNATURE_FAILURE,
    X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, X509_V_ERR_EC_KEY_EXPLICIT_PARAMS,
    X509_V_ERR_EE_KEY_TOO_SMALL, X509_V_ERR_EMAIL_MISMATCH, X509_V_ERR_EMPTY_SUBJECT_ALT_NAME,
    X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL, X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD,
    X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD, X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3,
    X509_V_ERR_HOSTNAME_MISMATCH, X509_V_ERR_INVALID_CA, X509_V_ERR_INVALID_CALL,
    X509_V_ERR_INVALID_NON_CA, X509_V_ERR_INVALID_PURPOSE, X509_V_ERR_IP_ADDRESS_MISMATCH,
    X509_V_ERR_ISSUER_NAME_EMPTY, X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA,
    X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER, X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER,
    X509_V_ERR_OUT_OF_MEM, X509_V_ERR_PATH_LENGTH_EXCEEDED, X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA,
    X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN, X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED,
    X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED, X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION,
    X509_V_ERR_RPK_UNTRUSTED, X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
    X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY, X509_V_ERR_STORE_LOOKUP,
    X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL, X509_V_ERR_SUBJECT_NAME_EMPTY,
    X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
    X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION, X509_V_ERR_UNSPECIFIED, X509_V_FLAG_ALLOW_PROXY_CERTS,
    X509_V_FLAG_CHECK_SS_SIGNATURE, X509_V_FLAG_IGNORE_CRITICAL, X509_V_FLAG_NO_ALT_CHAINS,
    X509_V_FLAG_PARTIAL_CHAIN, X509_V_FLAG_POLICY_CHECK, X509_V_FLAG_TRUSTED_FIRST,
    X509_V_FLAG_X509_STRICT, X509_V_OK, X509_VERSION_3, stack_st_X509,
};

use super::cert::{
    OSSL_STACK_OF_X509_free, X509_chain_check_suiteb, X509_free, X509_get_issuer_name,
    X509_get_pubkey_parameters, X509_get_subject_name, X509_get_version, X509_get0_extensions,
    X509_get0_pubkey, X509_up_ref, X509_verify, cert_of,
};
use super::ctx::{
    Ctx, X509_STORE_CTX_free, X509_STORE_CTX_init, X509_STORE_CTX_new_ex,
    X509_STORE_CTX_set0_trusted_stack, best_issuer_sk, check_cert_time, ctx_of, verify_cb_cert,
};
use super::name::{
    X509_NAME_ENTRY_free, X509_NAME_ENTRY_get_object, X509_NAME_ENTRY_set, X509_NAME_cmp,
    X509_NAME_delete_entry, X509_NAME_dup, X509_NAME_entry_count, X509_NAME_free,
    X509_NAME_get_entry,
};
use super::purpose::{
    X509_add_cert, X509_add_certs, X509_check_ca, X509_check_purpose, X509_cmp,
    X509_get_signature_info, X509_self_signed, cache_view, likely_issued, signing_allowed,
};
use super::trust::X509_check_trust;
use super::vpm::Param;
use crate::err;
use crate::stack::{
    OPENSSL_sk_delete_ptr, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop,
    OPENSSL_sk_push, OPENSSL_sk_set, OPENSSL_sk_value,
};
use crate::x509v3::check::{X509_check_email, X509_check_host, X509_check_ip};
use crate::x509v3::ncons::{NAME_CONSTRAINTS_check, NAME_CONSTRAINTS_check_CN};

/// The security levels' minimum bits (`minbits_table`).
const MINBITS: [c_int; 5] = [80, 112, 128, 192, 256];

/// A flag of `x509_vfy.h` (all positive) as the parameters' `unsigned long`.
fn flag(v: c_int) -> c_ulong {
    c_ulong::from(v.cast_unsigned())
}

/// An `EXFLAG_*` or `KU_*` (all positive) as the cache's `u32`.
fn ex(v: c_int) -> u32 {
    v.cast_unsigned()
}

/// The context's parameters.
fn params(c: &mut Ctx) -> Option<&mut Param> {
    // SAFETY: a context's parameters are NULL or live, and its own.
    unsafe { c.param.cast::<Param>().as_mut() }
}

/// The context's security level.
fn level_of(c: &Ctx) -> c_int {
    // SAFETY: as for `params`.
    unsafe { c.param.cast::<Param>().as_ref() }.map_or(-1, |p| p.auth_level)
}

/// The context's flags.
fn flags_of(c: &Ctx) -> c_ulong {
    // SAFETY: as for `params`.
    unsafe { c.param.cast::<Param>().as_ref() }.map_or(0, |p| p.flags)
}

/// The context.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn c<'a>(ctx: *mut X509_STORE_CTX) -> Option<&'a mut Ctx> {
    // SAFETY: the caller's guarantee.
    unsafe { ctx_of(ctx) }
}

/// The chain's certificate at `i`.
fn at(chain: *mut stack_st_X509, i: c_int) -> *mut X509 {
    // SAFETY: a context's chain is NULL or a live list.
    unsafe { OPENSSL_sk_value(chain.cast(), i) }.cast()
}

/// The chain's length.
fn len(chain: *mut stack_st_X509) -> c_int {
    // SAFETY: as above.
    unsafe { OPENSSL_sk_num(chain.cast()) }
}

/// `CB_FAIL_IF`: whether to stop, having reported `err` for `x` at `depth` when `cond`.
///
/// # Safety
/// `ctx` is a live context; `x` is NULL or a live certificate.
unsafe fn fails(
    cond: bool,
    ctx: *mut X509_STORE_CTX,
    x: *mut X509,
    depth: c_int,
    err: c_int,
) -> bool {
    // SAFETY: the caller's guarantee.
    cond && unsafe { verify_cb_cert(ctx, x, depth, err) } == 0
}

/// Whether the context has a DANE state (libssl's, which comes later).
fn dane_enabled(c: &Ctx) -> bool {
    if c.dane.is_null() {
        return false;
    }
    crate::stub::unimplemented("DANE verification (with libssl)")
}

// Security levels.

/// `check_key_level`.
fn key_level_ok(c: &Ctx, pkey: *const EVP_PKEY) -> bool {
    let level = level_of(c);
    if level <= 0 {
        return true;
    }
    if pkey.is_null() {
        return false;
    }
    let idx = usize::try_from(level).unwrap_or(1).clamp(1, MINBITS.len()) - 1;
    // SAFETY: a live key.
    let bits = unsafe { crate::evp::pkey::EVP_PKEY_get_security_bits(pkey) };
    MINBITS.get(idx).is_some_and(|&m| bits >= m)
}

/// `check_cert_key_level`.
///
/// # Safety
/// `cert` is a live certificate.
unsafe fn cert_key_level_ok(c: &Ctx, cert: *mut X509) -> bool {
    // SAFETY: the caller's guarantee.
    key_level_ok(c, unsafe { X509_get0_pubkey(cert) })
}

/// `check_sig_level`.
///
/// # Safety
/// `cert` is a live certificate.
unsafe fn sig_level_ok(c: &Ctx, cert: *mut X509) -> bool {
    let level = level_of(c);
    if level <= 0 {
        return true;
    }
    let idx = usize::try_from(level).unwrap_or(1).clamp(1, MINBITS.len()) - 1;
    let mut secbits: c_int = -1;
    let none = ptr::null_mut();
    // SAFETY: the caller's certificate; a local and no other outputs.
    if unsafe { X509_get_signature_info(cert, none, none, &raw mut secbits, none.cast()) } == 0 {
        return false;
    }
    MINBITS.get(idx).is_some_and(|&m| secbits >= m)
}

/// `check_curve`: 1 unless the key is EC with explicit parameters (0); -1 without a key.
///
/// # Safety
/// `cert` is a live certificate.
unsafe fn check_curve(cert: *mut X509) -> c_int {
    // SAFETY: the caller's guarantee.
    let pkey = unsafe { X509_get0_pubkey(cert) };
    if pkey.is_null() {
        return -1;
    }
    // SAFETY: a live key.
    if unsafe { crate::evp::pkey::EVP_PKEY_get_id(pkey) } != EVP_PKEY_EC {
        return 1;
    }
    let mut val: c_int = 0;
    // SAFETY: the key; a static name; a local.
    let ret = unsafe {
        crate::evp::pkey::params::EVP_PKEY_get_int_param(
            pkey,
            OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS
                .as_ptr()
                .cast(),
            &raw mut val,
        )
    };
    if ret == 1 { c_int::from(val == 0) } else { -1 }
}

/// `check_auth_level`.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn check_auth_level(ctx: *mut X509_STORE_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return 0;
    };
    if params(cx).map_or(-1, |p| p.auth_level) <= 0 {
        return 1;
    }
    let chain = cx.chain;
    let num = len(chain);
    for i in 0..num {
        let cert = at(chain, i);
        // SAFETY: the context.
        let Some(cx) = (unsafe { c(ctx) }) else {
            return 0;
        };
        // SAFETY: a certificate of the chain.
        let key_bad = i > 0 && !unsafe { cert_key_level_ok(cx, cert) };
        // SAFETY: as above.
        if unsafe { fails(key_bad, ctx, cert, i, X509_V_ERR_CA_KEY_TOO_SMALL) } {
            return 0;
        }
        // SAFETY: the context.
        let Some(cx) = (unsafe { c(ctx) }) else {
            return 0;
        };
        // SAFETY: as above.
        let sig_bad = i < num - 1 && !unsafe { sig_level_ok(cx, cert) };
        // SAFETY: as above.
        if unsafe { fails(sig_bad, ctx, cert, i, X509_V_ERR_CA_MD_TOO_WEAK) } {
            return 0;
        }
    }
    1
}

// Trust.

/// `lookup_cert_match`: the trusted certificate equal to `x`, with a reference: 1, 0, -1.
///
/// # Safety
/// `ctx` is a live context; `x` is a live certificate.
unsafe fn lookup_cert_match(
    result: &mut *mut X509,
    ctx: *mut X509_STORE_CTX,
    x: *mut X509,
) -> c_int {
    *result = ptr::null_mut();
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return -1;
    };
    let lookup = cx.lookup_certs;
    // SAFETY: no preconditions.
    unsafe { err::ERR_set_mark() };
    // SAFETY: the certificate's subject.
    let name = unsafe { X509_get_subject_name(x) };
    // SAFETY: the context's function, with no reference into the context held.
    let certs = lookup.map_or(ptr::null_mut(), |f| unsafe { f(ctx, name) });
    // SAFETY: no preconditions.
    unsafe { err::ERR_pop_to_mark() };
    if certs.is_null() {
        return -1;
    }
    let mut found = ptr::null_mut();
    for i in 0..len(certs) {
        let xtmp = at(certs, i);
        // SAFETY: certificates.
        if unsafe { X509_cmp(xtmp, x) } == 0 {
            found = xtmp;
            break;
        }
    }
    let mut ret = c_int::from(!found.is_null());
    if ret != 0 {
        // SAFETY: a certificate of the list.
        if unsafe { X509_up_ref(found) } == 0 {
            ret = -1;
        } else {
            *result = found;
        }
    }
    // SAFETY: the list and its references.
    unsafe { OSSL_STACK_OF_X509_free(certs) };
    ret
}

/// `check_trust`: whether the chain from `num_untrusted` on holds a trusted (or rejected)
/// certificate, or, for partial chains, ends in one.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn check_trust(ctx: *mut X509_STORE_CTX, num_untrusted: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return X509_TRUST_UNTRUSTED;
    };
    if dane_enabled(cx) {
        return X509_TRUST_UNTRUSTED;
    }
    let chain = cx.chain;
    let num = len(chain);
    let trust_id = params(cx).map_or(0, |p| p.trust);
    let partial = flags_of(cx) & flag(X509_V_FLAG_PARTIAL_CHAIN) != 0;
    let rejected = |x: *mut X509, i: c_int| {
        // SAFETY: the caller's context; a certificate of the chain.
        if unsafe { verify_cb_cert(ctx, x, i, X509_V_ERR_CERT_REJECTED) } == 0 {
            X509_TRUST_REJECTED
        } else {
            X509_TRUST_UNTRUSTED
        }
    };
    for i in num_untrusted..num {
        let x = at(chain, i);
        // SAFETY: a certificate of the chain.
        let trust = unsafe { X509_check_trust(x, trust_id, 0) };
        if trust == X509_TRUST_TRUSTED {
            return X509_TRUST_TRUSTED;
        }
        if trust == X509_TRUST_REJECTED {
            return rejected(x, i);
        }
    }
    if num_untrusted < num {
        return if partial {
            X509_TRUST_TRUSTED
        } else {
            X509_TRUST_UNTRUSTED
        };
    }
    if num_untrusted == num && partial {
        let x = at(chain, 0);
        let mut mx = ptr::null_mut();
        // SAFETY: the context; its leaf.
        let res = unsafe { lookup_cert_match(&mut mx, ctx, x) };
        if res < 0 {
            return res;
        }
        if res == 0 {
            return X509_TRUST_UNTRUSTED;
        }
        // SAFETY: the trusted copy.
        let trust = unsafe { X509_check_trust(mx, trust_id, 0) };
        if trust == X509_TRUST_REJECTED {
            // SAFETY: its reference.
            unsafe { X509_free(mx) };
            return rejected(x, 0);
        }
        // SAFETY: the chain, which takes the copy's reference in place of the leaf's.
        unsafe { OPENSSL_sk_set(chain.cast(), 0, mx.cast()) };
        // SAFETY: the leaf's reference, the chain's.
        unsafe { X509_free(x) };
        // SAFETY: the context.
        if let Some(cx) = unsafe { c(ctx) } {
            cx.num_untrusted = 0;
        }
        return X509_TRUST_TRUSTED;
    }
    X509_TRUST_UNTRUSTED
}

// Building the chain.

/// `get1_trusted_issuer`: the context's issuer lookup, with no chain while it runs.
///
/// # Safety
/// `ctx` is a live context; `cert` is a live certificate.
unsafe fn trusted_issuer(
    issuer: &mut *mut X509,
    ctx: *mut X509_STORE_CTX,
    cert: *mut X509,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return -1;
    };
    let saved = cx.chain;
    cx.chain = ptr::null_mut();
    let get = cx.get_issuer;
    // SAFETY: the context's function, with no reference into it held.
    let ok = get.map_or(0, |f| unsafe { f(issuer, ctx, cert) });
    // SAFETY: as above.
    if let Some(cx) = unsafe { c(ctx) } {
        cx.chain = saved;
    }
    ok
}

/// `build_chain`: 1 for a trusted chain, 0 if rejected (or a failure the callback didn't
/// accept), -1 on failure.
///
/// # Safety
/// `ctx` is a live context with its leaf alone in its chain.
#[expect(
    clippy::too_many_lines,
    reason = "OpenSSL's one function, kept whole to compare"
)]
unsafe fn build_chain(ctx: *mut X509_STORE_CTX) -> c_int {
    const DO_UNTRUSTED: u32 = 1;
    const DO_TRUSTED: u32 = 2;
    const DO_ALTERNATE: u32 = 4;
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return -1;
    };
    let int_err = |ctx: *mut X509_STORE_CTX, sk: *mut stack_st_X509| {
        err::raise(ERR_LIB_X509, ERR_R_INTERNAL_ERROR, "build_chain");
        // SAFETY: the context.
        if let Some(cx) = unsafe { c(ctx) } {
            cx.error = X509_V_ERR_UNSPECIFIED;
        }
        // SAFETY: the working list, without references.
        unsafe { OPENSSL_sk_free(sk.cast()) };
        -1
    };
    let memerr = |ctx: *mut X509_STORE_CTX, sk: *mut stack_st_X509| {
        // SAFETY: the context.
        if let Some(cx) = unsafe { c(ctx) } {
            cx.error = X509_V_ERR_OUT_OF_MEM;
        }
        // SAFETY: as above.
        unsafe { OPENSSL_sk_free(sk.cast()) };
        -1
    };
    if len(cx.chain) != 1 || cx.num_untrusted != 1 {
        return int_err(ctx, ptr::null_mut());
    }
    dane_enabled(cx);
    let flags = flags_of(cx);
    let mut search: u32 = if cx.untrusted.is_null() {
        0
    } else {
        DO_UNTRUSTED
    };
    let mut may_alternate = false;
    if search == 0 || flags & flag(X509_V_FLAG_TRUSTED_FIRST) != 0 {
        search |= DO_TRUSTED;
    } else if flags & flag(X509_V_FLAG_NO_ALT_CHAINS) == 0 {
        may_alternate = true;
    }
    let may_trusted = true;
    // SAFETY: no preconditions.
    let sk_untrusted = unsafe { OPENSSL_sk_new_null() }.cast::<stack_st_X509>();
    if sk_untrusted.is_null() {
        err::raise(ERR_LIB_X509, ERR_R_CRYPTO_LIB, "build_chain");
        return memerr(ctx, ptr::null_mut());
    }
    let add_default = c_int::try_from(X509_ADD_FLAG_DEFAULT).unwrap_or(0);
    // SAFETY: the working list; the context's untrusted certificates.
    if unsafe { X509_add_certs(sk_untrusted, cx.untrusted, add_default) } == 0 {
        err::raise(ERR_LIB_X509, ERR_R_X509_LIB, "build_chain");
        return memerr(ctx, sk_untrusted);
    }
    let Some(p) = params(cx) else {
        return int_err(ctx, sk_untrusted);
    };
    if p.depth > c_int::MAX / 2 {
        p.depth = c_int::MAX / 2;
    }
    let max_depth = p.depth.saturating_add(1);
    let mut trust = X509_TRUST_UNTRUSTED;
    let mut alt_untrusted: c_int = 0;
    while search != 0 {
        // SAFETY: the context, again after the callbacks.
        let Some(cx) = (unsafe { c(ctx) }) else {
            return -1;
        };
        let mut num = len(cx.chain);
        cx.error_depth = num - 1;
        if search & DO_TRUSTED != 0 {
            let i = if search & DO_ALTERNATE != 0 {
                alt_untrusted
            } else {
                num
            };
            let curr = at(cx.chain, i - 1);
            let mut issuer: *mut X509 = ptr::null_mut();
            let mut ok = if num > max_depth {
                0
            } else {
                // SAFETY: the context; a certificate of its chain.
                unsafe { trusted_issuer(&mut issuer, ctx, curr) }
            };
            if ok < 0 {
                trust = -1;
                // SAFETY: the context.
                if let Some(cx) = unsafe { c(ctx) } {
                    cx.error = X509_V_ERR_STORE_LOOKUP;
                }
                break;
            }
            if ok > 0 {
                // SAFETY: a certificate of the chain.
                let mut self_signed = unsafe { X509_self_signed(curr, 0) };
                if self_signed < 0 {
                    // SAFETY: the issuer's reference.
                    unsafe { X509_free(issuer) };
                    return int_err(ctx, sk_untrusted);
                }
                // SAFETY: the context.
                let Some(cx) = (unsafe { c(ctx) }) else {
                    return -1;
                };
                if search & DO_ALTERNATE != 0 {
                    if !(num > i && i > 0 && self_signed == 0) {
                        // SAFETY: as above.
                        unsafe { X509_free(issuer) };
                        return int_err(ctx, sk_untrusted);
                    }
                    search &= !DO_ALTERNATE;
                    while num > i {
                        // SAFETY: the context's chain.
                        let last = unsafe { OPENSSL_sk_pop(cx.chain.cast()) };
                        // SAFETY: the chain's last, whose reference it held.
                        unsafe { X509_free(last.cast()) };
                        num -= 1;
                    }
                    cx.num_untrusted = num;
                }
                if self_signed == 0 {
                    // SAFETY: the chain; the issuer, whose reference it takes.
                    if unsafe { OPENSSL_sk_push(cx.chain.cast(), issuer.cast()) } == 0 {
                        // SAFETY: as above.
                        unsafe { X509_free(issuer) };
                        err::raise(ERR_LIB_X509, ERR_R_CRYPTO_LIB, "build_chain");
                        return memerr(ctx, sk_untrusted);
                    }
                    // SAFETY: the issuer.
                    self_signed = unsafe { X509_self_signed(issuer, 0) };
                    if self_signed < 0 {
                        return int_err(ctx, sk_untrusted);
                    }
                // SAFETY: certificates.
                } else if unsafe { X509_cmp(curr, issuer) } != 0 {
                    // SAFETY: as above.
                    unsafe { X509_free(issuer) };
                    ok = 0;
                } else {
                    // SAFETY: the chain's certificate being replaced.
                    unsafe { X509_free(curr) };
                    num -= 1;
                    cx.num_untrusted = num;
                    // SAFETY: the chain, which takes the issuer's reference.
                    unsafe { OPENSSL_sk_set(cx.chain.cast(), num, issuer.cast()) };
                }
                if ok != 0 {
                    // SAFETY: the context.
                    let Some(cx) = (unsafe { c(ctx) }) else {
                        return -1;
                    };
                    if cx.num_untrusted > num {
                        return int_err(ctx, sk_untrusted);
                    }
                    search &= !DO_UNTRUSTED;
                    // SAFETY: the context.
                    trust = unsafe { check_trust(ctx, num) };
                    if trust != X509_TRUST_UNTRUSTED {
                        break;
                    }
                    if self_signed == 0 {
                        continue;
                    }
                }
            }
            if search & DO_UNTRUSTED == 0 {
                if search & DO_ALTERNATE != 0 {
                    alt_untrusted -= 1;
                    if alt_untrusted > 0 {
                        continue;
                    }
                }
                // SAFETY: the context.
                let Some(cx) = (unsafe { c(ctx) }) else {
                    return -1;
                };
                if !may_alternate || search & DO_ALTERNATE != 0 || cx.num_untrusted < 2 {
                    break;
                }
                search |= DO_ALTERNATE;
                alt_untrusted = cx.num_untrusted - 1;
            }
        }
        if search & DO_UNTRUSTED != 0 {
            // SAFETY: the context.
            let Some(cx) = (unsafe { c(ctx) }) else {
                return -1;
            };
            let num = len(cx.chain);
            if num != cx.num_untrusted {
                return int_err(ctx, sk_untrusted);
            }
            let curr = at(cx.chain, num - 1);
            // SAFETY: a certificate of the chain.
            let issuer = if unsafe { X509_self_signed(curr, 0) } > 0 || num > max_depth {
                ptr::null_mut()
            } else {
                // SAFETY: the context; the working list; the certificate.
                unsafe { best_issuer_sk(ctx, false, true, sk_untrusted, curr) }
            };
            if issuer.is_null() {
                search &= !DO_UNTRUSTED;
                if may_trusted {
                    search |= DO_TRUSTED;
                }
                continue;
            }
            // SAFETY: the working list, which doesn't own it.
            unsafe { OPENSSL_sk_delete_ptr(sk_untrusted.cast(), issuer.cast()) };
            // SAFETY: the context.
            let Some(cx) = (unsafe { c(ctx) }) else {
                return -1;
            };
            let up = c_int::try_from(X509_ADD_FLAG_UP_REF).unwrap_or(0);
            // SAFETY: the chain; the issuer.
            if unsafe { X509_add_cert(cx.chain, issuer, up) } == 0 {
                return int_err(ctx, sk_untrusted);
            }
            cx.num_untrusted += 1;
        }
    }
    // SAFETY: the working list, without references.
    unsafe { OPENSSL_sk_free(sk_untrusted.cast()) };
    if trust < 0 {
        return trust;
    }
    // SAFETY: the context.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return -1;
    };
    let num = len(cx.chain);
    if num <= max_depth && trust == X509_TRUST_UNTRUSTED && num == cx.num_untrusted {
        // SAFETY: the context.
        trust = unsafe { check_trust(ctx, num) };
    }
    if trust == X509_TRUST_TRUSTED {
        return 1;
    }
    if trust == X509_TRUST_REJECTED {
        return 0;
    }
    // SAFETY: the context.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return -1;
    };
    let error = cx.error;
    if [
        X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD,
        X509_V_ERR_CERT_NOT_YET_VALID,
        X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD,
        X509_V_ERR_CERT_HAS_EXPIRED,
    ]
    .contains(&error)
    {
        return 0;
    }
    if error != X509_V_OK {
        // SAFETY: the context.
        return unsafe { verify_cb_cert(ctx, ptr::null_mut(), num - 1, error) };
    }
    // SAFETY: as above.
    if unsafe {
        fails(
            num > max_depth,
            ctx,
            ptr::null_mut(),
            num - 1,
            X509_V_ERR_CERT_CHAIN_TOO_LONG,
        )
    } {
        return 0;
    }
    // SAFETY: the context.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return -1;
    };
    let top = at(cx.chain, num - 1);
    let num_untrusted = cx.num_untrusted;
    // SAFETY: a certificate of the chain.
    let err = if unsafe { X509_self_signed(top, 0) } > 0 {
        if num == 1 {
            X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
        } else {
            X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
        }
    } else if num_untrusted < num {
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
    } else {
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
    };
    // SAFETY: as above.
    unsafe { verify_cb_cert(ctx, ptr::null_mut(), num - 1, err) }
}

// The checks.

/// `check_purpose`.
///
/// # Safety
/// `ctx` is a live context; `x` is a live certificate.
unsafe fn check_purpose(
    ctx: *mut X509_STORE_CTX,
    x: *mut X509,
    purpose: c_int,
    depth: c_int,
    must_be_ca: c_int,
) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return false;
    };
    let (p_purpose, p_trust) = params(cx).map_or((0, 0), |p| (p.purpose, p.trust));
    let strict = flags_of(cx) & flag(X509_V_FLAG_X509_STRICT) != 0;
    let mut tr_ok = X509_TRUST_UNTRUSTED;
    if depth >= cx.num_untrusted && purpose == p_purpose {
        // SAFETY: the certificate.
        tr_ok = unsafe { X509_check_trust(x, p_trust, X509_TRUST_NO_SS_COMPAT.cast_signed()) };
    }
    if tr_ok == X509_TRUST_TRUSTED {
        return true;
    }
    if tr_ok != X509_TRUST_REJECTED {
        // SAFETY: as above.
        match unsafe { X509_check_purpose(x, purpose, c_int::from(must_be_ca > 0)) } {
            1 => return true,
            0 => {}
            _ if !strict => return true,
            _ => {}
        }
    }
    // SAFETY: as above.
    unsafe { verify_cb_cert(ctx, x, depth, X509_V_ERR_INVALID_PURPOSE) != 0 }
}

/// `check_extensions`.
///
/// # Safety
/// `ctx` is a live context.
#[expect(
    clippy::too_many_lines,
    reason = "OpenSSL's one function, kept whole to compare"
)]
unsafe fn check_extensions(ctx: *mut X509_STORE_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return 0;
    };
    let chain = cx.chain;
    let num = len(chain);
    let flags = flags_of(cx);
    let strict = flags & flag(X509_V_FLAG_X509_STRICT) != 0;
    let (allow_proxy, purpose) = if cx.parent.is_null() {
        (
            flags & flag(X509_V_FLAG_ALLOW_PROXY_CERTS) != 0,
            params(cx).map_or(0, |p| p.purpose),
        )
    } else {
        (false, X509_PURPOSE_CRL_SIGN)
    };
    let mut must_be_ca: c_int = -1;
    let mut plen: c_long = 0;
    let mut proxy_path_length: c_long = 0;
    macro_rules! fail_if {
        ($cond:expr, $x:expr, $i:expr, $err:expr) => {
            // SAFETY: the context; a certificate of the chain.
            if unsafe { fails($cond, ctx, $x, $i, $err) } {
                return 0;
            }
        };
    }
    for i in 0..num {
        let x = at(chain, i);
        // SAFETY: a certificate of the chain (its cache is filled by `X509_check_ca` below; the
        // flags read here are as they stand, as OpenSSL's).
        let v = unsafe { cache_view(x) };
        fail_if!(
            flags & flag(X509_V_FLAG_IGNORE_CRITICAL) == 0 && v.flags & ex(EXFLAG_CRITICAL) != 0,
            x,
            i,
            X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION
        );
        fail_if!(
            !allow_proxy && v.flags & ex(EXFLAG_PROXY) != 0,
            x,
            i,
            X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED
        );
        // SAFETY: as above.
        let ret = unsafe { X509_check_ca(x) };
        match must_be_ca {
            -1 => fail_if!(strict && ret != 1 && ret != 0, x, i, X509_V_ERR_INVALID_CA),
            0 => fail_if!(ret != 0, x, i, X509_V_ERR_INVALID_NON_CA),
            _ => fail_if!(
                ret == 0 || ((i + 1 < num || strict) && ret != 1),
                x,
                i,
                X509_V_ERR_INVALID_CA
            ),
        }
        // SAFETY: as above, the cache filled now.
        let v = unsafe { cache_view(x) };
        if num > 1 {
            // SAFETY: as above.
            let r = unsafe { check_curve(x) };
            fail_if!(r < 0, x, i, X509_V_ERR_UNSPECIFIED);
            fail_if!(r == 0, x, i, X509_V_ERR_EC_KEY_EXPLICIT_PARAMS);
        }
        if strict && num > 1 {
            let is_ca = v.flags & ex(EXFLAG_CA) != 0;
            if v.pathlen != -1 {
                fail_if!(!is_ca, x, i, X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA);
                fail_if!(
                    v.kusage & ex(KU_KEY_CERT_SIGN) == 0,
                    x,
                    i,
                    X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN
                );
            }
            fail_if!(
                is_ca
                    && v.flags & ex(EXFLAG_BCONS) != 0
                    && v.flags & ex(EXFLAG_BCONS_CRITICAL) == 0,
                x,
                i,
                X509_V_ERR_CA_BCONS_NOT_CRITICAL
            );
            if is_ca {
                fail_if!(
                    v.flags & ex(EXFLAG_KUSAGE) == 0,
                    x,
                    i,
                    X509_V_ERR_CA_CERT_MISSING_KEY_USAGE
                );
            } else {
                fail_if!(
                    v.kusage & ex(KU_KEY_CERT_SIGN) != 0,
                    x,
                    i,
                    X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA
                );
            }
            // SAFETY: the certificate.
            let (iname, sname) = (unsafe { X509_get_issuer_name(x) }, unsafe {
                X509_get_subject_name(x)
            });
            // SAFETY: its names.
            let issuer_entries = unsafe { X509_NAME_entry_count(iname) };
            // SAFETY: as above.
            let subject_entries = unsafe { X509_NAME_entry_count(sname) };
            fail_if!(issuer_entries == 0, x, i, X509_V_ERR_ISSUER_NAME_EMPTY);
            fail_if!(
                (is_ca || v.kusage & ex(KU_CRL_SIGN) != 0 || v.altname.is_null())
                    && subject_entries == 0,
                x,
                i,
                X509_V_ERR_SUBJECT_NAME_EMPTY
            );
            fail_if!(
                subject_entries == 0
                    && !v.altname.is_null()
                    && v.flags & ex(EXFLAG_SAN_CRITICAL) == 0,
                x,
                i,
                X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL
            );
            // SAFETY: its alternative names, live with the cache.
            let alts = unsafe { OPENSSL_sk_num(v.altname.cast()) };
            fail_if!(
                !v.altname.is_null() && alts <= 0,
                x,
                i,
                X509_V_ERR_EMPTY_SUBJECT_ALT_NAME
            );
            // SAFETY: the certificate.
            let algs_differ = unsafe { cert_of(x) }.is_some_and(|ce| {
                // SAFETY: its two algorithms.
                (unsafe {
                    super::algor::X509_ALGOR_cmp(
                        &raw const ce.sig_alg,
                        &raw const ce.cert_info.signature,
                    )
                }) != 0
            });
            fail_if!(
                algs_differ,
                x,
                i,
                X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY
            );
            fail_if!(
                !v.akid.is_null() && v.flags & ex(EXFLAG_AKID_CRITICAL) != 0,
                x,
                i,
                X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL
            );
            fail_if!(
                !v.skid.is_null() && v.flags & ex(EXFLAG_SKID_CRITICAL) != 0,
                x,
                i,
                X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL
            );
            // SAFETY: as above.
            if unsafe { X509_get_version(x) } >= c_long::from(X509_VERSION_3) {
                // SAFETY: its authority key identifier, live with the cache.
                let no_keyid = unsafe { v.akid.as_ref() }.is_none_or(|a| a.keyid.is_null());
                fail_if!(
                    i + 1 < num && no_keyid,
                    x,
                    i,
                    X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER
                );
                fail_if!(
                    is_ca && v.skid.is_null(),
                    x,
                    i,
                    X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER
                );
            } else {
                // SAFETY: as above.
                let list = unsafe { X509_get0_extensions(x) };
                // SAFETY: its extensions.
                let exts = unsafe { OPENSSL_sk_num(list.cast()) };
                fail_if!(exts > 0, x, i, X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3);
            }
        }
        // SAFETY: the context; the certificate.
        if purpose >= X509_PURPOSE_MIN && !unsafe { check_purpose(ctx, x, purpose, i, must_be_ca) }
        {
            return 0;
        }
        fail_if!(
            i > 1 && v.pathlen != -1 && plen > v.pathlen.saturating_add(proxy_path_length),
            x,
            i,
            X509_V_ERR_PATH_LENGTH_EXCEEDED
        );
        if i > 0 && v.flags & ex(EXFLAG_SI) == 0 {
            plen += 1;
        }
        if v.flags & ex(EXFLAG_PROXY) != 0 {
            if v.pcpathlen != -1 {
                fail_if!(
                    proxy_path_length > v.pcpathlen,
                    x,
                    i,
                    X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED
                );
                proxy_path_length = v.pcpathlen;
            }
            proxy_path_length += 1;
            must_be_ca = 0;
        } else {
            must_be_ca = 1;
        }
    }
    1
}

/// `check_hosts`: whether the leaf matches one of the hosts (any, for none), noting the name.
///
/// # Safety
/// `x` is a live certificate; `p` is the context's parameters.
unsafe fn check_hosts(x: *mut X509, p: &mut Param) -> bool {
    // SAFETY: its own peer name, or NULL.
    unsafe { crate::mem::release(p.peername.cast()) };
    p.peername = ptr::null_mut();
    // SAFETY: its hosts.
    let n = unsafe { OPENSSL_sk_num(p.hosts.cast()) };
    for i in 0..n {
        // SAFETY: an index within its hosts, C strings.
        let name = unsafe { OPENSSL_sk_value(p.hosts.cast(), i) }.cast::<c_char>();
        // SAFETY: the certificate; the name; its peer name's slot.
        if unsafe { X509_check_host(x, name, 0, p.hostflags, &raw mut p.peername) } > 0 {
            return true;
        }
    }
    n == 0
}

/// `check_id`: the leaf against the expected hosts, email, and IP address.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn check_id(ctx: *mut X509_STORE_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return 0;
    };
    let x = cx.cert;
    let Some(p) = params(cx) else { return 1 };
    let report = |err| {
        // SAFETY: the context; its leaf.
        unsafe { verify_cb_cert(ctx, x, 0, err) != 0 }
    };
    // SAFETY: the leaf; the context's parameters.
    if !p.hosts.is_null() && !unsafe { check_hosts(x, p) } && !report(X509_V_ERR_HOSTNAME_MISMATCH)
    {
        return 0;
    }
    // SAFETY: as above, after the callback.
    let Some(p) = (unsafe { c(ctx) }).and_then(|cx| params(cx)) else {
        return 0;
    };
    let email_bad = !p.email.is_null() && {
        // SAFETY: the leaf; the email, of its length.
        unsafe { X509_check_email(x, p.email, p.emaillen, 0) <= 0 }
    };
    if email_bad && !report(X509_V_ERR_EMAIL_MISMATCH) {
        return 0;
    }
    // SAFETY: as above.
    let Some(p) = (unsafe { c(ctx) }).and_then(|cx| params(cx)) else {
        return 0;
    };
    let ip_bad = !p.ip.is_null() && {
        // SAFETY: the leaf; the address, of its length.
        unsafe { X509_check_ip(x, p.ip, p.iplen, 0) <= 0 }
    };
    if ip_bad && !report(X509_V_ERR_IP_ADDRESS_MISMATCH) {
        return 0;
    }
    1
}

/// `has_san_id`: whether the certificate has an alternative name of `gtype`.
///
/// # Safety
/// `x` is a live certificate.
unsafe fn has_san_id(x: *mut X509, gtype: c_int) -> bool {
    // SAFETY: the caller's guarantee; no outputs.
    let gs = unsafe {
        super::purpose::X509_get_ext_d2i(
            x,
            rustyssl_abi::NID_subject_alt_name,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if gs.is_null() {
        return false;
    }
    // SAFETY: the decoded names.
    let n = unsafe { OPENSSL_sk_num(gs.cast()) };
    let found = (0..n).any(|i| {
        // SAFETY: an index within the names.
        let g = unsafe { OPENSSL_sk_value(gs.cast(), i) }.cast::<GENERAL_NAME>();
        // SAFETY: a name of the list.
        unsafe { g.as_ref() }.is_some_and(|g| g.type_ == gtype)
    });
    // SAFETY: decoded above.
    unsafe { crate::x509v3::genn::GENERAL_NAMES_free(gs.cast()) };
    found
}

/// The proxy certificate's name rule: its subject is its issuer's with one more RDN, a
/// single common name.
///
/// # Safety
/// `x` is a live certificate.
unsafe fn proxy_name_error(x: *mut X509) -> c_int {
    // SAFETY: the caller's guarantee.
    let subject = unsafe { X509_get_subject_name(x) };
    // SAFETY: as above.
    let issuer = unsafe { X509_get_issuer_name(x) };
    // SAFETY: the names.
    let count = unsafe { X509_NAME_entry_count(subject) };
    let last = count - 1;
    // SAFETY: as above.
    if last < 1 || count != unsafe { X509_NAME_entry_count(issuer) }.saturating_add(1) {
        return X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION;
    }
    // SAFETY: the subject's last two entries.
    let (a, b) = (unsafe { X509_NAME_get_entry(subject, last) }, unsafe {
        X509_NAME_get_entry(subject, last - 1)
    });
    // SAFETY: entries of the subject.
    if unsafe { X509_NAME_ENTRY_set(a) } == unsafe { X509_NAME_ENTRY_set(b) } {
        return X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION;
    }
    // SAFETY: the subject.
    let tmp = unsafe { X509_NAME_dup(subject) };
    if tmp.is_null() {
        return X509_V_ERR_OUT_OF_MEM;
    }
    // SAFETY: the copy.
    let entry = unsafe { X509_NAME_delete_entry(tmp, last) };
    // SAFETY: the deleted entry.
    let obj = unsafe { X509_NAME_ENTRY_get_object(entry) };
    // SAFETY: its type.
    let nid = unsafe { crate::objects::OBJ_obj2nid(obj) };
    // SAFETY: the copy; the issuer.
    let err = if nid != NID_commonName || unsafe { X509_NAME_cmp(tmp, issuer) } != 0 {
        X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION
    } else {
        X509_V_OK
    };
    // SAFETY: the deleted entry, ours now.
    unsafe { X509_NAME_ENTRY_free(entry) };
    // SAFETY: the copy.
    unsafe { X509_NAME_free(tmp) };
    err
}

/// `check_name_constraints`.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn check_name_constraints(ctx: *mut X509_STORE_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return 0;
    };
    let chain = cx.chain;
    let hostflags = params(cx).map_or(0, |p| p.hostflags);
    let flagged = |f: c_int| hostflags & f.cast_unsigned() != 0;
    let num = len(chain);
    for i in (0..num).rev() {
        let x = at(chain, i);
        // SAFETY: a certificate of the chain.
        let v = unsafe { cache_view(x) };
        if i != 0 && v.flags & ex(EXFLAG_SI) != 0 {
            continue;
        }
        if v.flags & ex(EXFLAG_PROXY) != 0 {
            // SAFETY: as above.
            let err = unsafe { proxy_name_error(x) };
            if err == X509_V_ERR_OUT_OF_MEM {
                err::raise(
                    ERR_LIB_X509,
                    rustyssl_abi::ERR_R_ASN1_LIB,
                    "check_name_constraints",
                );
                // SAFETY: the context.
                if let Some(cx) = unsafe { c(ctx) } {
                    cx.error = X509_V_ERR_OUT_OF_MEM;
                }
                return -1;
            }
            // SAFETY: the context; the certificate.
            if unsafe { fails(err != X509_V_OK, ctx, x, i, err) } {
                return 0;
            }
        }
        for j in ((i + 1)..num).rev() {
            // SAFETY: a CA of the chain.
            let nc = unsafe { cache_view(at(chain, j)) }.nc;
            if nc.is_null() {
                continue;
            }
            // SAFETY: the certificate; the CA's constraints.
            let mut rv = unsafe { NAME_CONSTRAINTS_check(x, nc) };
            if rv == X509_V_OK
                && i == 0
                && !flagged(X509_CHECK_FLAG_NEVER_CHECK_SUBJECT)
                // SAFETY: the leaf.
                && (flagged(X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT) || !unsafe { has_san_id(x, GEN_DNS) })
            {
                // SAFETY: as above.
                rv = unsafe { NAME_CONSTRAINTS_check_CN(x, nc) };
            }
            if rv == X509_V_ERR_OUT_OF_MEM {
                return -1;
            }
            // SAFETY: the context; the certificate.
            if rv != X509_V_OK && unsafe { verify_cb_cert(ctx, x, i, rv) } == 0 {
                return 0;
            }
        }
    }
    1
}

/// `internal_verify`: the signatures (from the top, the trust anchor's own only if asked) and
/// the validity times, each certificate reported to the callback as OK too.
pub(crate) unsafe extern "C" fn internal_verify(ctx: *mut X509_STORE_CTX) -> c_int {
    crate::ffi::guard(
        ERR_LIB_X509,
        "internal_verify",
        || 0,
        move || {
            // SAFETY: the context the default verification is called with.
            unsafe { verify(ctx) }
        },
    )
}

/// The body of [`internal_verify`].
///
/// # Safety
/// `ctx` is a live context.
unsafe fn verify(ctx: *mut X509_STORE_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return 0;
    };
    let cb = cx.verify_cb;
    let call = |ok: c_int| {
        // SAFETY: the context's callback, with no reference into it held.
        cb.map_or(0, |f| unsafe { f(ok, ctx) })
    };
    if !cx.rpk.is_null() {
        return c_int::from(call(c_int::from(cx.error == X509_V_OK)) != 0);
    }
    let chain = cx.chain;
    let flags = flags_of(cx);
    let mut n = len(chain) - 1;
    let mut xi = at(chain, n);
    let mut xs = xi;
    cx.error_depth = n;
    if cx.bare_ta_signed != 0 {
        xi = ptr::null_mut();
    // SAFETY: the top of the chain.
    } else if unsafe { likely_issued(xi, xi) } != X509_V_OK
        && flags & flag(X509_V_FLAG_PARTIAL_CHAIN) == 0
    {
        if n > 0 {
            n -= 1;
            cx.error_depth = n;
            xs = at(chain, n);
        // SAFETY: the context; the certificate.
        } else if unsafe { fails(true, ctx, xi, 0, X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE) } {
            return 0;
        }
    }
    while n >= 0 {
        // SAFETY: the issuer, if there's one.
        let xi_flags = unsafe { cache_view(xi) }.flags;
        let check_ss =
            flags & flag(X509_V_FLAG_CHECK_SS_SIGNATURE) != 0 && xi_flags & ex(EXFLAG_SS) != 0;
        if !xi.is_null() && (xs != xi || check_ss) {
            let issuer_depth = n + c_int::from(xs != xi);
            let ret = if xs == xi && xi_flags & ex(EXFLAG_CA) == 0 {
                X509_V_OK
            } else {
                // SAFETY: the certificates.
                unsafe { signing_allowed(xi, xs) }
            };
            // SAFETY: the context; the issuer.
            if unsafe { fails(ret != X509_V_OK, ctx, xi, issuer_depth, ret) } {
                return 0;
            }
            // SAFETY: the issuer.
            let pkey = unsafe { X509_get0_pubkey(xi) };
            if pkey.is_null() {
                // SAFETY: as above.
                if unsafe {
                    fails(
                        true,
                        ctx,
                        xi,
                        issuer_depth,
                        X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY,
                    )
                } {
                    return 0;
                }
            } else {
                // SAFETY: the certificate; its issuer's key.
                let bad = unsafe { X509_verify(xs, pkey) } <= 0;
                // SAFETY: as above.
                if unsafe { fails(bad, ctx, xs, n, X509_V_ERR_CERT_SIGNATURE_FAILURE) } {
                    return 0;
                }
            }
        }
        // SAFETY: the context; the certificate.
        if unsafe { check_cert_time(ctx, xs, n) } == 0 {
            return 0;
        }
        // SAFETY: the context.
        let Some(cx) = (unsafe { c(ctx) }) else {
            return 0;
        };
        cx.current_issuer = xi;
        cx.current_cert = xs;
        cx.error_depth = n;
        let cb = cx.verify_cb;
        // SAFETY: the context's callback, with no reference into it held.
        if cb.map_or(0, |f| unsafe { f(1, ctx) }) == 0 {
            return 0;
        }
        n -= 1;
        if n >= 0 {
            xi = xs;
            xs = at(chain, n);
        }
    }
    1
}

/// `verify_chain`.
///
/// # Safety
/// `ctx` is a live context with its leaf in its chain.
unsafe fn verify_chain(ctx: *mut X509_STORE_CTX) -> c_int {
    // SAFETY: the caller's guarantee, for each step.
    let mut ok = unsafe { build_chain(ctx) };
    if ok <= 0 {
        return ok;
    }
    // SAFETY: as above.
    ok = unsafe { check_extensions(ctx) };
    if ok <= 0 {
        return ok;
    }
    // SAFETY: as above.
    ok = unsafe { check_auth_level(ctx) };
    if ok <= 0 {
        return ok;
    }
    // SAFETY: as above.
    ok = unsafe { check_id(ctx) };
    if ok <= 0 {
        return ok;
    }
    // SAFETY: the context.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return -1;
    };
    // SAFETY: its chain.
    if unsafe { X509_get_pubkey_parameters(ptr::null_mut(), cx.chain) } == 0 {
        return -1;
    }
    let revocation = cx.check_revocation;
    // SAFETY: the context's function, with no reference into it held.
    ok = revocation.map_or(1, |f| unsafe { f(ctx) });
    if ok <= 0 {
        return ok;
    }
    // SAFETY: the context.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return -1;
    };
    let flags = flags_of(cx);
    // SAFETY: its error depth's slot; its chain.
    let err = unsafe {
        X509_chain_check_suiteb(&raw mut cx.error_depth, ptr::null_mut(), cx.chain, flags)
    };
    let depth = cx.error_depth;
    // SAFETY: the context.
    if unsafe { fails(err != X509_V_OK, ctx, ptr::null_mut(), depth, err) } {
        return 0;
    }
    // SAFETY: the context.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return -1;
    };
    let verify_fn = cx.verify;
    ok = match verify_fn {
        // SAFETY: the context's function, with no reference into it held.
        Some(f) => unsafe { f(ctx) },
        // SAFETY: as above, the default.
        None => unsafe { verify(ctx) },
    };
    if ok <= 0 {
        return ok;
    }
    // SAFETY: the context.
    ok = unsafe { check_name_constraints(ctx) };
    if ok <= 0 {
        return ok;
    }
    // SAFETY: as above.
    ok = unsafe { rfc3779(ctx) };
    if ok <= 0 {
        return ok;
    }
    // SAFETY: the context.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return -1;
    };
    if flags_of(cx) & flag(X509_V_FLAG_POLICY_CHECK) != 0 {
        let policy = cx.check_policy;
        // SAFETY: the context's function, with no reference into it held.
        ok = policy.map_or(1, |f| unsafe { f(ctx) });
    }
    ok
}

/// The RFC 3779 resource checks (`X509v3_asid_validate_path`, `X509v3_addr_validate_path`).
///
/// # Safety
/// `ctx` is a live context.
unsafe fn rfc3779(ctx: *mut X509_STORE_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    let ok = unsafe { crate::x509v3::rfc3779::X509v3_asid_validate_path(ctx) };
    if ok <= 0 {
        return ok;
    }
    // SAFETY: as above.
    unsafe { crate::x509v3::rfc3779::X509v3_addr_validate_path(ctx) }
}

/// `x509_verify_x509`.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn verify_x509(ctx: *mut X509_STORE_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return -1;
    };
    if cx.cert.is_null() {
        err::raise(
            ERR_LIB_X509,
            X509_R_NO_CERT_SET_FOR_US_TO_VERIFY,
            "x509_verify_x509",
        );
        cx.error = X509_V_ERR_INVALID_CALL;
        return -1;
    }
    if !cx.chain.is_null() {
        err::raise(
            ERR_LIB_X509,
            ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
            "x509_verify_x509",
        );
        cx.error = X509_V_ERR_INVALID_CALL;
        return -1;
    }
    // SAFETY: no preconditions.
    cx.chain = unsafe { OPENSSL_sk_new_null() }.cast();
    let up = c_int::try_from(X509_ADD_FLAG_UP_REF).unwrap_or(0);
    // SAFETY: the new chain; the leaf.
    if cx.chain.is_null() || unsafe { X509_add_cert(cx.chain, cx.cert, up) } == 0 {
        cx.error = X509_V_ERR_OUT_OF_MEM;
        return -1;
    }
    cx.num_untrusted = 1;
    let leaf = cx.cert;
    // SAFETY: the leaf.
    let small = !unsafe { cert_key_level_ok(cx, leaf) };
    // SAFETY: the context; the leaf.
    if unsafe { fails(small, ctx, leaf, 0, X509_V_ERR_EE_KEY_TOO_SMALL) } {
        return 0;
    }
    // SAFETY: the context.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return -1;
    };
    dane_enabled(cx);
    // SAFETY: the context, its leaf in its chain.
    let ret = unsafe { verify_chain(ctx) };
    // SAFETY: the context.
    if let Some(cx) = unsafe { c(ctx) }
        && ret <= 0
        && cx.error == X509_V_OK
    {
        cx.error = X509_V_ERR_UNSPECIFIED;
    }
    ret
}

/// `x509_verify_rpk`: a raw public key, by its level and the callback (or the verification
/// function).
///
/// # Safety
/// `ctx` is a live context with a raw public key.
unsafe fn verify_rpk(ctx: *mut X509_STORE_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return -1;
    };
    let small = !key_level_ok(cx, cx.rpk);
    // SAFETY: the context.
    if unsafe { fails(small, ctx, ptr::null_mut(), 0, X509_V_ERR_EE_KEY_TOO_SMALL) } {
        return 0;
    }
    // SAFETY: as above.
    let Some(cx) = (unsafe { c(ctx) }) else {
        return -1;
    };
    cx.error = X509_V_ERR_RPK_UNTRUSTED;
    dane_enabled(cx);
    let (verify_fn, cb, error) = (cx.verify, cx.verify_cb, cx.error);
    let ret = match verify_fn {
        // SAFETY: the context's function, with no reference into it held.
        Some(f) => unsafe { f(ctx) },
        // SAFETY: as above.
        None => {
            let ok = c_int::from(error == X509_V_OK);
            // SAFETY: the context's callback, with no reference into it held.
            c_int::from(cb.map_or(0, |f| unsafe { f(ok, ctx) }) != 0)
        }
    };
    // SAFETY: the context.
    if let Some(cx) = unsafe { c(ctx) }
        && ret <= 0
        && cx.error == X509_V_OK
    {
        cx.error = X509_V_ERR_UNSPECIFIED;
    }
    ret
}

crate::ffi::ffi_export! {
    /// Verifies the context's certificate (or raw public key): 1 if its chain is trusted and
    /// passes the checks (or the callback accepted each failure), 0 if not, -1 on failure;
    /// the error, its depth, and the chain are in the context.
    ///
    /// # Safety
    /// `ctx` is NULL or a live, initialized context.
    pub unsafe extern "C" fn X509_verify_cert(ctx: *mut X509_STORE_CTX) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(cx) = (unsafe { c(ctx) }) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509_verify_cert");
            return -1;
        };
        if cx.rpk.is_null() {
            // SAFETY: as above.
            unsafe { verify_x509(ctx) }
        } else {
            // SAFETY: as above.
            unsafe { verify_rpk(ctx) }
        }
    }
}

crate::ffi::ffi_export! {
    /// Verifies as `X509_verify_cert`, taking the certificate from the untrusted ones' first
    /// if the context has none.
    ///
    /// # Safety
    /// As for [`X509_verify_cert`].
    pub unsafe extern "C" fn X509_STORE_CTX_verify(ctx: *mut X509_STORE_CTX) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(cx) = (unsafe { c(ctx) }) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509_STORE_CTX_verify");
            return -1;
        };
        if !cx.rpk.is_null() {
            // SAFETY: as above.
            return unsafe { verify_rpk(ctx) };
        }
        if cx.cert.is_null() && len(cx.untrusted) >= 1 {
            cx.cert = at(cx.untrusted, 0);
        }
        // SAFETY: as above.
        unsafe { verify_x509(ctx) }
    }
}

crate::ffi::ffi_export! {
    /// The chain of `target` built from `certs` and `store` (without checking it): with a
    /// store, `certs` are untrusted and the chain must be trusted; without one, `certs` are
    /// the trusted ones. Self-signed certificates are left out of a longer chain unless
    /// `with_self_signed`. NULL on failure.
    ///
    /// # Safety
    /// `target` is NULL or a live certificate; `certs` is NULL or a live list of
    /// certificates; `store` is NULL or a live store; `propq` is NULL or a C string.
    pub unsafe extern "C" fn X509_build_chain(target: *mut X509, certs: *mut stack_st_X509, store: *mut X509_STORE, with_self_signed: c_int, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut stack_st_X509
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        if target.is_null() {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509_build_chain");
            return ptr::null_mut();
        }
        let finish_chain = !store.is_null();
        // SAFETY: the caller's context.
        let ctx = unsafe { X509_STORE_CTX_new_ex(libctx, propq) };
        if ctx.is_null() {
            return ptr::null_mut();
        }
        let untrusted = if finish_chain { certs } else { ptr::null_mut() };
        let mut result: *mut stack_st_X509 = ptr::null_mut();
        // SAFETY: the new context; the caller's objects.
        if unsafe { X509_STORE_CTX_init(ctx, store, target, untrusted) } != 0 {
            if !finish_chain {
                // SAFETY: as above.
                unsafe { X509_STORE_CTX_set0_trusted_stack(ctx, certs) };
            }
            // SAFETY: the new context.
            let built = match unsafe { c(ctx) } {
                Some(cx) => {
                    // SAFETY: no preconditions.
                    cx.chain = unsafe { OPENSSL_sk_new_null() }.cast();
                    let up = c_int::try_from(X509_ADD_FLAG_UP_REF).unwrap_or(0);
                    // SAFETY: the new chain; the target.
                    if cx.chain.is_null() || unsafe { X509_add_cert(cx.chain, target, up) } == 0 {
                        cx.error = X509_V_ERR_OUT_OF_MEM;
                        None
                    } else {
                        cx.num_untrusted = 1;
                        // SAFETY: the context, its target in its chain.
                        Some(unsafe { build_chain(ctx) })
                    }
                }
                None => None,
            };
            if let Some(r) = built
                && (r != 0 || !finish_chain)
            {
                // SAFETY: the context.
                let chain = unsafe { c(ctx) }.map_or(ptr::null_mut(), |cx| cx.chain);
                let mut flags = c_int::try_from(X509_ADD_FLAG_UP_REF).unwrap_or(0);
                if len(chain) > 1 && with_self_signed == 0 {
                    flags |= c_int::try_from(X509_ADD_FLAG_NO_SS).unwrap_or(0);
                }
                // SAFETY: no preconditions.
                result = unsafe { OPENSSL_sk_new_null() }.cast();
                // SAFETY: the new list; the chain.
                if !result.is_null() && unsafe { X509_add_certs(result, chain, flags) } == 0 {
                    // SAFETY: the new list and the references it took.
                    unsafe { OSSL_STACK_OF_X509_free(result) };
                    result = ptr::null_mut();
                }
            }
        }
        // SAFETY: the new context.
        unsafe { X509_STORE_CTX_free(ctx) };
        result
    }
}
