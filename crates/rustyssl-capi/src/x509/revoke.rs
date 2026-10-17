//! Revocation (`x509_vfy.c`): the context's default `check_revocation`, `check_crl`, and
//! `cert_crl`. With `X509_V_FLAG_CRL_CHECK` the leaf (with `X509_V_FLAG_CRL_CHECK_ALL`, every
//! certificate of the chain) is checked against CRLs until every reason is covered: the
//! context's CRLs and then the store's are scored (issuer name, authority key identifier and
//! the CRL issuer's place, distribution point scope, times, critical extensions), the best one
//! is taken with its delta CRL (`X509_V_FLAG_USE_DELTAS`), each is checked (key usage, scope,
//! the CRL issuer's own path, times, Suite B, the signature), and then the certificate is
//! looked up in them. Each failure goes to the verification callback, which may accept it.

use core::ffi::{c_int, c_uint, c_ulong};
use core::ptr;

use libc::time_t;
use rustyssl_abi::{
    CRL_REASON_REMOVE_FROM_CRL, CRLDP_ALL_REASONS, DIST_POINT, DIST_POINT_NAME, ERR_LIB_X509,
    EXFLAG_CA, EXFLAG_CRITICAL, EXFLAG_FRESHEST, EXFLAG_KUSAGE, EXFLAG_PROXY, GEN_DIRNAME,
    GENERAL_NAME, GENERAL_NAMES, IDP_INDIRECT, IDP_INVALID, IDP_ONLYATTR, IDP_ONLYCA, IDP_ONLYUSER,
    IDP_REASONS, KU_CRL_SIGN, NID_authority_key_identifier, NID_issuing_distribution_point, X509,
    X509_CRL, X509_NAME, X509_REVOKED, X509_STORE_CTX, X509_V_ERR_CERT_REVOKED,
    X509_V_ERR_CRL_HAS_EXPIRED, X509_V_ERR_CRL_NOT_YET_VALID, X509_V_ERR_CRL_PATH_VALIDATION_ERROR,
    X509_V_ERR_CRL_SIGNATURE_FAILURE, X509_V_ERR_DIFFERENT_CRL_SCOPE,
    X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD, X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD,
    X509_V_ERR_INVALID_EXTENSION, X509_V_ERR_KEYUSAGE_NO_CRL_SIGN,
    X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY, X509_V_ERR_UNABLE_TO_GET_CRL,
    X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER, X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION,
    X509_V_FLAG_CRL_CHECK, X509_V_FLAG_CRL_CHECK_ALL, X509_V_FLAG_EXTENDED_CRL_SUPPORT,
    X509_V_FLAG_IGNORE_CRITICAL, X509_V_FLAG_NO_CHECK_TIME, X509_V_FLAG_USE_CHECK_TIME,
    X509_V_FLAG_USE_DELTAS, X509_V_OK, stack_st_X509, stack_st_X509_CRL,
};

use super::cert::{X509_cmp_time, X509_get_issuer_name, X509_get_subject_name, X509_get0_pubkey};
use super::crl::{
    Crl, X509_CRL_check_suiteb, X509_CRL_free, X509_CRL_get_ext, X509_CRL_get_ext_by_NID,
    X509_CRL_get0_by_cert, X509_CRL_up_ref, X509_CRL_verify, revoked_of,
};
use super::ctx::{
    Ctx, X509_STORE_CTX_free, X509_STORE_CTX_init, X509_STORE_CTX_new_ex,
    X509_STORE_CTX_set0_param, crl_free, ctx_of,
};
use super::ext::X509_EXTENSION_get_data;
use super::name::{X509_NAME_cmp, X509_NAME_free};
use super::purpose::{X509_check_akid, X509_cmp, cache_view};
use super::verify::X509_verify_cert;
use super::vpm::Param;
use crate::asn1::integer::ASN1_INTEGER_cmp;
use crate::asn1::string::ASN1_OCTET_STRING_cmp;
use crate::asn1::time::ASN1_TIME_diff;
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value};
use crate::x509v3::crld::full_name;
use crate::x509v3::genn::GENERAL_NAME_cmp;

// The parts of a CRL's score (`CRL_SCORE_*`), highest first.
/// No unhandled critical extensions.
const SCORE_NOCRITICAL: c_int = 0x100;
/// The certificate is within the CRL's scope.
const SCORE_SCOPE: c_int = 0x080;
/// The CRL's times are valid.
const SCORE_TIME: c_int = 0x040;
/// The CRL's issuer name is the certificate's.
const SCORE_ISSUER_NAME: c_int = 0x020;
/// What a CRL that's probably valid scores at least.
const SCORE_VALID: c_int = SCORE_NOCRITICAL | SCORE_TIME | SCORE_SCOPE;
/// The CRL's issuer is the certificate's.
const SCORE_ISSUER_CERT: c_int = 0x018;
/// The CRL's issuer is on the certificate's path.
const SCORE_SAME_PATH: c_int = 0x008;
/// The CRL's issuer matches its authority key identifier.
const SCORE_AKID: c_int = 0x004;
/// There's a delta CRL with valid times.
const SCORE_TIME_DELTA: c_int = 0x002;

/// Every reason (`CRLDP_ALL_REASONS`), as the context keeps them.
const ALL_REASONS: c_uint = CRLDP_ALL_REASONS.cast_unsigned();

/// A flag of `x509_vfy.h` (all positive) as the parameters' `unsigned long`.
fn flag(v: c_int) -> c_ulong {
    c_ulong::from(v.cast_unsigned())
}

/// An `EXFLAG_*` or `KU_*` (all positive) as the cache's `u32`.
fn ex(v: c_int) -> u32 {
    v.cast_unsigned()
}

/// The context's flags.
fn flags_of(c: &Ctx) -> c_ulong {
    // SAFETY: a context's parameters are NULL or live, and its own.
    unsafe { c.param.cast::<Param>().as_ref() }.map_or(0, |p| p.flags)
}

/// The context.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn cx<'a>(ctx: *mut X509_STORE_CTX) -> Option<&'a mut Ctx> {
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

/// The names' entry at `i`.
fn name_at<'a>(names: *mut GENERAL_NAMES, i: c_int) -> Option<&'a GENERAL_NAME> {
    // SAFETY: the names are NULL or a live list of live names.
    let p = unsafe { OPENSSL_sk_value(names.cast(), i) }.cast::<GENERAL_NAME>();
    // SAFETY: as above.
    unsafe { p.as_ref() }
}

/// The names' count.
fn names_len(names: *mut GENERAL_NAMES) -> c_int {
    // SAFETY: as above.
    unsafe { OPENSSL_sk_num(names.cast()) }
}

/// The name of a directory name, or `None` for another kind.
fn dirname(gen_name: &GENERAL_NAME) -> Option<*mut X509_NAME> {
    // SAFETY: a directory name's member.
    (gen_name.type_ == GEN_DIRNAME).then_some(unsafe { gen_name.d.directoryName })
}

/// The CRL behind a pointer, read only (a list may hold one CRL twice), or `None` for NULL.
///
/// # Safety
/// `x` is NULL or a live CRL.
unsafe fn crl_ref<'a>(x: *const X509_CRL) -> Option<&'a Crl> {
    // SAFETY: the caller's guarantee; a CRL is a `Crl`.
    unsafe { x.cast::<Crl>().as_ref() }
}

/// `verify_cb_crl`: reports `err` to the verification callback (the current certificate and
/// depth as they are): its answer.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn verify_cb_crl(ctx: *mut X509_STORE_CTX, err: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { cx(ctx) }) else {
        return 0;
    };
    c.error = err;
    let cb = c.verify_cb;
    // SAFETY: the context's callback, with no reference into the context held.
    cb.map_or(0, |f| unsafe { f(0, ctx) })
}

/// `check_revocation`: nothing to check without `X509_V_FLAG_CRL_CHECK`; otherwise the leaf
/// (or with `X509_V_FLAG_CRL_CHECK_ALL` every certificate; a CRL path's context checks none
/// but with it) goes through `check_cert`.
pub(crate) unsafe extern "C" fn check_revocation(ctx: *mut X509_STORE_CTX) -> c_int {
    crate::ffi::guard(
        ERR_LIB_X509,
        "check_revocation",
        || 0,
        move || {
            // SAFETY: the context the verification is called with.
            let Some(c) = (unsafe { cx(ctx) }) else {
                return 0;
            };
            let flags = flags_of(c);
            if flags & flag(X509_V_FLAG_CRL_CHECK) == 0 {
                return 1;
            }
            let last = if flags & flag(X509_V_FLAG_CRL_CHECK_ALL) != 0 {
                len(c.chain) - 1
            } else if !c.parent.is_null() {
                return 1;
            } else {
                0
            };
            for i in 0..=last {
                // SAFETY: as above.
                let Some(c) = (unsafe { cx(ctx) }) else {
                    return 0;
                };
                c.error_depth = i;
                // SAFETY: as above.
                let ok = unsafe { check_cert(ctx) };
                if ok == 0 {
                    return ok;
                }
            }
            1
        },
    )
}

/// `check_cert`: checks the chain's certificate at the error depth against CRLs until every
/// reason is covered.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn check_cert(ctx: *mut X509_STORE_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { cx(ctx) }) else {
        return 0;
    };
    let x = at(c.chain, c.error_depth);
    c.current_cert = x;
    c.current_issuer = ptr::null_mut();
    c.current_crl_score = 0;
    c.current_reasons = 0;
    // SAFETY: the chain's certificate.
    if unsafe { cache_view(x) }.flags & ex(EXFLAG_PROXY) != 0 {
        return 1;
    }
    let mut crl: *mut X509_CRL = ptr::null_mut();
    let mut dcrl: *mut X509_CRL = ptr::null_mut();
    let mut ok = 0;
    loop {
        // SAFETY: as above.
        let Some(c) = (unsafe { cx(ctx) }) else {
            ok = 0;
            break;
        };
        if c.current_reasons == ALL_REASONS {
            break;
        }
        let last_reasons = c.current_reasons;
        if let Some(get_crl) = c.get_crl {
            let mut crl_issuer = ptr::null_mut();
            let mut reasons = 0;
            // SAFETY: the context's function, with no reference into it held.
            ok = unsafe { get_crl(ctx, &raw mut crl, x) };
            if !crl.is_null() {
                // SAFETY: the context; the function's CRL; the certificate.
                let score = unsafe { get_crl_score(ctx, &mut crl_issuer, &mut reasons, crl, x) };
                // SAFETY: as above.
                let Some(c) = (unsafe { cx(ctx) }) else {
                    ok = 0;
                    break;
                };
                c.current_crl_score = score;
                c.current_issuer = crl_issuer;
                c.current_reasons = reasons;
            }
        } else {
            // SAFETY: as above.
            ok = unsafe { get_crl_delta(ctx, &mut crl, &mut dcrl, x) };
        }
        if ok == 0 {
            // SAFETY: as above.
            ok = unsafe { verify_cb_crl(ctx, X509_V_ERR_UNABLE_TO_GET_CRL) };
            break;
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { cx(ctx) }) else {
            ok = 0;
            break;
        };
        c.current_crl = crl;
        let (check, cert) = (c.check_crl, c.cert_crl);
        // SAFETY: the context's functions, with no reference into it held.
        let check = |crl| check.map_or(0, |f| unsafe { f(ctx, crl) });
        // SAFETY: as above.
        let cert = |crl| cert.map_or(0, |f| unsafe { f(ctx, crl, x) });
        ok = check(crl);
        if ok == 0 {
            break;
        }
        if dcrl.is_null() {
            ok = 1;
        } else {
            ok = check(dcrl);
            if ok == 0 {
                break;
            }
            ok = cert(dcrl);
            if ok == 0 {
                break;
            }
        }
        if ok != 2 {
            ok = cert(crl);
            if ok == 0 {
                break;
            }
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { cx(ctx) }) else {
            ok = 0;
            break;
        };
        c.current_crl = ptr::null_mut();
        // SAFETY: the references this loop took.
        unsafe { X509_CRL_free(crl) };
        // SAFETY: as above.
        unsafe { X509_CRL_free(dcrl) };
        crl = ptr::null_mut();
        dcrl = ptr::null_mut();
        if last_reasons == c.current_reasons {
            // SAFETY: as above.
            ok = unsafe { verify_cb_crl(ctx, X509_V_ERR_UNABLE_TO_GET_CRL) };
            break;
        }
    }
    // SAFETY: as above.
    unsafe { X509_CRL_free(crl) };
    // SAFETY: as above.
    unsafe { X509_CRL_free(dcrl) };
    // SAFETY: as above.
    if let Some(c) = unsafe { cx(ctx) } {
        c.current_crl = ptr::null_mut();
    }
    ok
}

/// `check_crl_time`: whether the CRL's times are valid at the context's time. Without
/// `notify`, only the answer; with it, each failure goes to the callback (with the CRL as the
/// current one), which may accept it.
///
/// # Safety
/// `ctx` is a live context; `crl` is a live CRL.
unsafe fn check_crl_time(ctx: *mut X509_STORE_CTX, crl: *mut X509_CRL, notify: bool) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { cx(ctx) }) else {
        return 0;
    };
    // SAFETY: a context's parameters are NULL or live, and its own.
    let Some(p) = (unsafe { c.param.cast::<Param>().as_ref() }) else {
        return 0;
    };
    let mut check_time = p.check_time;
    let ptime: *mut time_t = if p.flags & flag(X509_V_FLAG_USE_CHECK_TIME) != 0 {
        &raw mut check_time
    } else if p.flags & flag(X509_V_FLAG_NO_CHECK_TIME) != 0 {
        return 1;
    } else {
        ptr::null_mut()
    };
    if notify {
        c.current_crl = crl;
    }
    // SAFETY: the caller's CRL.
    let Some(cr) = (unsafe { crl_ref(crl) }) else {
        return 0;
    };
    let (last_update, next_update) = (cr.crl.last_update, cr.crl.next_update);
    // SAFETY: as above.
    let rejects = |err| !notify || unsafe { verify_cb_crl(ctx, err) } == 0;
    // SAFETY: the CRL's time; the time, or NULL for now.
    let i = unsafe { X509_cmp_time(last_update, ptime) };
    if i == 0 && rejects(X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD) {
        return 0;
    }
    if i > 0 && rejects(X509_V_ERR_CRL_NOT_YET_VALID) {
        return 0;
    }
    if !next_update.is_null() {
        // SAFETY: as above.
        let i = unsafe { X509_cmp_time(next_update, ptime) };
        if i == 0 && rejects(X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD) {
            return 0;
        }
        // SAFETY: as above.
        let score = unsafe { cx(ctx) }.map_or(0, |c| c.current_crl_score);
        if i < 0 && score & SCORE_TIME_DELTA == 0 && rejects(X509_V_ERR_CRL_HAS_EXPIRED) {
            return 0;
        }
    }
    if notify {
        // SAFETY: as above.
        if let Some(c) = unsafe { cx(ctx) } {
            c.current_crl = ptr::null_mut();
        }
    }
    1
}

/// `get_crl_sk`: the best-scoring CRL of `crls` (the latest of equals) if it beats `*pscore`,
/// with a reference, its issuer, its score, its reasons, and its delta CRL: whether the best
/// one so far is probably valid.
///
/// # Safety
/// `ctx` is a live context; `*pcrl` and `*pdcrl` are NULL or CRLs the caller holds a
/// reference to; `crls` is NULL or a live list of live CRLs.
unsafe fn get_crl_sk(
    ctx: *mut X509_STORE_CTX,
    pcrl: &mut *mut X509_CRL,
    pdcrl: &mut *mut X509_CRL,
    pissuer: &mut *mut X509,
    pscore: &mut c_int,
    preasons: &mut c_uint,
    crls: *mut stack_st_X509_CRL,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { cx(ctx) }) else {
        return 0;
    };
    let x = c.current_cert;
    let mut best_score = *pscore;
    let mut best_reasons = 0;
    let mut best_crl: *mut X509_CRL = ptr::null_mut();
    let mut best_crl_issuer = ptr::null_mut();
    // SAFETY: the caller's list.
    for i in 0..unsafe { OPENSSL_sk_num(crls.cast()) } {
        // SAFETY: an index within the list.
        let crl = unsafe { OPENSSL_sk_value(crls.cast(), i) }.cast::<X509_CRL>();
        let mut crl_issuer = ptr::null_mut();
        let mut reasons = *preasons;
        // SAFETY: the context; the list's CRL; the current certificate.
        let crl_score = unsafe { get_crl_score(ctx, &mut crl_issuer, &mut reasons, crl, x) };
        if crl_score < best_score || crl_score == 0 {
            continue;
        }
        // Of equal scores, the latest.
        if crl_score == best_score && !best_crl.is_null() {
            // SAFETY: both CRLs are live.
            let (Some(best), Some(this)) = (unsafe { crl_ref(best_crl) }, unsafe { crl_ref(crl) })
            else {
                continue;
            };
            let (mut day, mut sec) = (0, 0);
            // SAFETY: their times.
            if unsafe {
                ASN1_TIME_diff(
                    &raw mut day,
                    &raw mut sec,
                    best.crl.last_update,
                    this.crl.last_update,
                )
            } == 0
            {
                continue;
            }
            if day <= 0 && sec <= 0 {
                continue;
            }
        }
        best_crl = crl;
        best_crl_issuer = crl_issuer;
        best_score = crl_score;
        best_reasons = reasons;
    }
    if !best_crl.is_null() {
        // SAFETY: the list's CRL.
        if unsafe { X509_CRL_up_ref(best_crl) } == 0 {
            return 0;
        }
        // SAFETY: the caller's reference.
        unsafe { X509_CRL_free(*pcrl) };
        *pcrl = best_crl;
        *pissuer = best_crl_issuer;
        *pscore = best_score;
        *preasons = best_reasons;
        // SAFETY: as above.
        unsafe { X509_CRL_free(*pdcrl) };
        *pdcrl = ptr::null_mut();
        // SAFETY: as above.
        unsafe { get_delta_sk(ctx, pdcrl, pscore, best_crl, crls) };
    }
    c_int::from(best_score >= SCORE_VALID)
}

/// `crl_extension_match`: whether the CRLs have the same extension `nid` (each at most once),
/// or neither has it.
///
/// # Safety
/// `a` and `b` are live CRLs.
unsafe fn crl_extension_match(a: *mut X509_CRL, b: *mut X509_CRL, nid: c_int) -> bool {
    let data = |crl: *mut X509_CRL| {
        // SAFETY: the caller's CRL.
        let i = unsafe { X509_CRL_get_ext_by_NID(crl, nid, -1) };
        if i < 0 {
            return Some(ptr::null_mut());
        }
        // SAFETY: as above.
        if unsafe { X509_CRL_get_ext_by_NID(crl, nid, i) } != -1 {
            return None;
        }
        // SAFETY: as above.
        let ext = unsafe { X509_CRL_get_ext(crl, i) };
        // SAFETY: its extension at `i`.
        Some(unsafe { X509_EXTENSION_get_data(ext) })
    };
    let (Some(exta), Some(extb)) = (data(a), data(b)) else {
        return false;
    };
    if exta.is_null() && extb.is_null() {
        return true;
    }
    if exta.is_null() || extb.is_null() {
        return false;
    }
    // SAFETY: their extensions' values.
    unsafe { ASN1_OCTET_STRING_cmp(exta, extb) == 0 }
}

/// `check_delta_base`: whether `delta` is a delta CRL of `base`.
///
/// # Safety
/// `delta` and `base` are live CRLs.
unsafe fn check_delta_base(delta: *mut X509_CRL, base: *mut X509_CRL) -> bool {
    // SAFETY: the caller's guarantee.
    let (Some(d), Some(b)) = (unsafe { crl_ref(delta) }, unsafe { crl_ref(base) }) else {
        return false;
    };
    if d.base_crl_number.is_null() || b.crl_number.is_null() {
        return false;
    }
    let (d_base, d_number, b_number) = (d.base_crl_number, d.crl_number, b.crl_number);
    // SAFETY: their issuers.
    if unsafe { X509_NAME_cmp(b.crl.issuer, d.crl.issuer) } != 0 {
        return false;
    }
    // SAFETY: the caller's CRLs.
    if !unsafe { crl_extension_match(delta, base, NID_authority_key_identifier) } {
        return false;
    }
    // SAFETY: as above.
    if !unsafe { crl_extension_match(delta, base, NID_issuing_distribution_point) } {
        return false;
    }
    // SAFETY: their numbers.
    if unsafe { ASN1_INTEGER_cmp(d_base, b_number) } > 0 {
        return false;
    }
    // SAFETY: as above.
    !d_number.is_null() && unsafe { ASN1_INTEGER_cmp(d_number, b_number) } > 0
}

/// `get_delta_sk`: with `X509_V_FLAG_USE_DELTAS` and a freshest CRL extension on the current
/// certificate or `base`, the first delta CRL of `base` in `crls` (with a reference), and
/// `SCORE_TIME_DELTA` if its times are valid.
///
/// # Safety
/// As for [`get_crl_sk`]; `*dcrl` is NULL; `base` is a live CRL.
unsafe fn get_delta_sk(
    ctx: *mut X509_STORE_CTX,
    dcrl: &mut *mut X509_CRL,
    pscore: &mut c_int,
    base: *mut X509_CRL,
    crls: *mut stack_st_X509_CRL,
) {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { cx(ctx) }) else {
        return;
    };
    if flags_of(c) & flag(X509_V_FLAG_USE_DELTAS) == 0 {
        return;
    }
    // SAFETY: the current certificate.
    let xflags = unsafe { cache_view(c.current_cert) }.flags;
    // SAFETY: the caller's CRL.
    let bflags = unsafe { crl_ref(base) }.map_or(0, |b| b.flags.cast_unsigned());
    if (xflags | bflags) & ex(EXFLAG_FRESHEST) == 0 {
        return;
    }
    // SAFETY: the caller's list.
    for i in 0..unsafe { OPENSSL_sk_num(crls.cast()) } {
        // SAFETY: an index within the list.
        let delta = unsafe { OPENSSL_sk_value(crls.cast(), i) }.cast::<X509_CRL>();
        // SAFETY: the list's CRL; the caller's.
        if unsafe { check_delta_base(delta, base) } {
            // SAFETY: as above.
            if unsafe { X509_CRL_up_ref(delta) } == 0 {
                *dcrl = ptr::null_mut();
                return;
            }
            *dcrl = delta;
            // SAFETY: the context; the CRL.
            if unsafe { check_crl_time(ctx, delta, false) } != 0 {
                *pscore |= SCORE_TIME_DELTA;
            }
            return;
        }
    }
    *dcrl = ptr::null_mut();
}

/// `get_crl_score`: how well `crl` suits `x` (0 for not at all), its issuer, and the reasons
/// covered with it.
///
/// # Safety
/// `ctx` is a live context; `crl` is a live CRL; `x` is a live certificate.
unsafe fn get_crl_score(
    ctx: *mut X509_STORE_CTX,
    pissuer: &mut *mut X509,
    preasons: &mut c_uint,
    crl: *mut X509_CRL,
    x: *mut X509,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { cx(ctx) }) else {
        return 0;
    };
    let extended = flags_of(c) & flag(X509_V_FLAG_EXTENDED_CRL_SUPPORT) != 0;
    // SAFETY: as above.
    let Some(cr) = (unsafe { crl_ref(crl) }) else {
        return 0;
    };
    let (idp_flags, idp_reasons) = (cr.idp_flags, cr.idp_reasons.cast_unsigned());
    let mut tmp_reasons = *preasons;
    let mut crl_score = 0;
    if idp_flags & IDP_INVALID != 0 {
        return 0;
    }
    // Delta CRLs are scored only as deltas.
    if !cr.base_crl_number.is_null() {
        return 0;
    }
    if !extended {
        if idp_flags & (IDP_INDIRECT | IDP_REASONS) != 0 {
            return 0;
        }
    } else if idp_flags & IDP_REASONS != 0 && idp_reasons & !tmp_reasons == 0 {
        return 0;
    }
    // SAFETY: the caller's certificate.
    let x_issuer = unsafe { X509_get_issuer_name(x) };
    // SAFETY: the certificate's issuer; the CRL's.
    if unsafe { X509_NAME_cmp(x_issuer, cr.crl.issuer) } != 0 {
        if idp_flags & IDP_INDIRECT == 0 {
            return 0;
        }
    } else {
        crl_score |= SCORE_ISSUER_NAME;
    }
    if cr.flags & EXFLAG_CRITICAL == 0 {
        crl_score |= SCORE_NOCRITICAL;
    }
    // SAFETY: the caller's context and CRL.
    if unsafe { check_crl_time(ctx, crl, false) } != 0 {
        crl_score |= SCORE_TIME;
    }
    // SAFETY: as above.
    unsafe { crl_akid_check(ctx, crl, pissuer, &mut crl_score) };
    if crl_score & SCORE_AKID == 0 {
        return 0;
    }
    let mut crl_reasons = 0;
    // SAFETY: the caller's certificate and CRL.
    if unsafe { crl_crldp_check(x, crl, crl_score, &mut crl_reasons) } {
        if crl_reasons & !tmp_reasons == 0 {
            return 0;
        }
        tmp_reasons |= crl_reasons;
        crl_score |= SCORE_SCOPE;
    }
    *preasons = tmp_reasons;
    crl_score
}

/// `crl_akid_check`: finds the CRL's issuer, by its name and authority key identifier: the
/// certificate's issuer, another certificate up the chain, or (with
/// `X509_V_FLAG_EXTENDED_CRL_SUPPORT`) an untrusted certificate, scoring which.
///
/// # Safety
/// `ctx` is a live context; `crl` is a live CRL.
unsafe fn crl_akid_check(
    ctx: *mut X509_STORE_CTX,
    crl: *mut X509_CRL,
    pissuer: &mut *mut X509,
    pcrl_score: &mut c_int,
) {
    // SAFETY: the caller's guarantee.
    let (Some(c), Some(cr)) = (unsafe { cx(ctx) }, unsafe { crl_ref(crl) }) else {
        return;
    };
    let (cnm, akid) = (cr.crl.issuer, cr.akid);
    let chain = c.chain;
    let mut cidx = c.error_depth;
    if cidx != len(chain) - 1 {
        cidx += 1;
    }
    let crl_issuer = at(chain, cidx);
    // SAFETY: the chain's certificate; the CRL's identifier.
    if unsafe { X509_check_akid(crl_issuer, akid) } == X509_V_OK
        && *pcrl_score & SCORE_ISSUER_NAME != 0
    {
        *pcrl_score |= SCORE_AKID | SCORE_ISSUER_CERT;
        *pissuer = crl_issuer;
        return;
    }
    let named = |x: *mut X509| {
        // SAFETY: a live certificate.
        let subject = unsafe { X509_get_subject_name(x) };
        // SAFETY: its subject; the CRL's issuer.
        let same = unsafe { X509_NAME_cmp(subject, cnm) } == 0;
        // SAFETY: as above.
        same && unsafe { X509_check_akid(x, akid) } == X509_V_OK
    };
    for i in cidx + 1..len(chain) {
        let crl_issuer = at(chain, i);
        if named(crl_issuer) {
            *pcrl_score |= SCORE_AKID | SCORE_SAME_PATH;
            *pissuer = crl_issuer;
            return;
        }
    }
    if flags_of(c) & flag(X509_V_FLAG_EXTENDED_CRL_SUPPORT) == 0 {
        return;
    }
    let untrusted = c.untrusted;
    for i in 0..len(untrusted) {
        let crl_issuer = at(untrusted, i);
        if named(crl_issuer) {
            *pissuer = crl_issuer;
            *pcrl_score |= SCORE_AKID;
            return;
        }
    }
}

/// `check_crl_path`: verifies the CRL issuer `x` in a context of its own (the parent's store,
/// untrusted certificates, CRLs, parameters, and callback), whose chain must end at the same
/// trust anchor: 1 if so, 0 if not or for a CRL path's own context, or the verification's
/// failure.
///
/// # Safety
/// `ctx` is a live context; `x` is NULL or a live certificate.
unsafe fn check_crl_path(ctx: *mut X509_STORE_CTX, x: *mut X509) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { cx(ctx) }) else {
        return 0;
    };
    if !c.parent.is_null() {
        return 0;
    }
    let (store, untrusted, crls, param, verify_cb, chain) =
        (c.store, c.untrusted, c.crls, c.param, c.verify_cb, c.chain);
    // SAFETY: no property query.
    let crl_ctx = unsafe { X509_STORE_CTX_new_ex(ptr::null_mut(), ptr::null()) };
    if crl_ctx.is_null() {
        return -1;
    }
    // SAFETY: the new context; the parent's store and certificates.
    let ret = if unsafe { X509_STORE_CTX_init(crl_ctx, store, x, untrusted) } == 0 {
        -1
    } else {
        // SAFETY: the new context.
        if let Some(cc) = unsafe { cx(crl_ctx) } {
            cc.crls = crls;
        }
        // SAFETY: as above; the parent's parameters, which the cleanup leaves alone for a
        // context with a parent.
        unsafe { X509_STORE_CTX_set0_param(crl_ctx, param) };
        // SAFETY: as above.
        if let Some(cc) = unsafe { cx(crl_ctx) } {
            cc.parent = ctx;
            cc.verify_cb = verify_cb;
        }
        // SAFETY: as above.
        let ret = unsafe { X509_verify_cert(crl_ctx) };
        if ret <= 0 {
            ret
        } else {
            // SAFETY: as above.
            let crl_chain = unsafe { cx(crl_ctx) }.map_or(ptr::null_mut(), |cc| cc.chain);
            // The same trust anchor (`check_crl_chain`).
            let cert_ta = at(chain, len(chain) - 1);
            let crl_ta = at(crl_chain, len(crl_chain) - 1);
            // SAFETY: the chains' certificates, or NULL.
            c_int::from(unsafe { X509_cmp(cert_ta, crl_ta) } == 0)
        }
    };
    // SAFETY: made above.
    unsafe { X509_STORE_CTX_free(crl_ctx) };
    ret
}

/// `crldp_full_name`: the full name of the distribution point's relative name: relative to
/// its CRL issuer's directory name, or else to `x`'s issuer.
///
/// # Safety
/// `x` is a live certificate; `dp`'s name is a live relative name.
unsafe fn crldp_full_name(x: *mut X509, dp: &DIST_POINT) -> *mut X509_NAME {
    let iname = (0..names_len(dp.CRLissuer))
        .find_map(|i| name_at(dp.CRLissuer, i).and_then(dirname))
        // SAFETY: the caller's certificate.
        .unwrap_or_else(|| unsafe { X509_get_issuer_name(x) });
    // SAFETY: the caller's guarantee.
    let Some(dpn) = (unsafe { dp.distpoint.as_ref() }) else {
        return ptr::null_mut();
    };
    // SAFETY: a relative name; a live name.
    unsafe { full_name(dpn, iname) }
}

/// `idp_check_dp`: whether the distribution point names `a` (with `aname` its full name if
/// relative) and `b` match: equal full names of relative names, a relative one's full name
/// among the other's directory names, or a name in common (and either missing).
///
/// # Safety
/// `a` and `b` are NULL or live names; `aname` is NULL or a live name.
unsafe fn idp_check_dp(
    a: *const DIST_POINT_NAME,
    aname: *const X509_NAME,
    b: *const DIST_POINT_NAME,
) -> bool {
    // SAFETY: the caller's guarantee.
    let (Some(a), Some(b)) = (unsafe { a.as_ref() }, unsafe { b.as_ref() }) else {
        return true;
    };
    let (nm, gens) = if a.type_ == 1 {
        if aname.is_null() {
            return false;
        }
        if b.type_ == 1 {
            if b.dpname.is_null() {
                return false;
            }
            // SAFETY: the names.
            return unsafe { X509_NAME_cmp(aname, b.dpname) } == 0;
        }
        // SAFETY: a full name's member.
        (aname, unsafe { b.name.fullname })
    } else if b.type_ == 1 {
        if b.dpname.is_null() {
            return false;
        }
        // SAFETY: as above.
        (b.dpname.cast_const(), unsafe { a.name.fullname })
    } else {
        (ptr::null(), ptr::null_mut())
    };
    if !nm.is_null() {
        return (0..names_len(gens)).any(|i| {
            name_at(gens, i).and_then(dirname).is_some_and(|d| {
                // SAFETY: the names.
                unsafe { X509_NAME_cmp(nm, d) == 0 }
            })
        });
    }
    // SAFETY: full names' members.
    let fa = unsafe { a.name.fullname };
    // SAFETY: as above.
    let fb = unsafe { b.name.fullname };
    (0..names_len(fa)).any(|i| {
        // SAFETY: the list's name.
        let gena = unsafe { OPENSSL_sk_value(fa.cast(), i) }.cast::<GENERAL_NAME>();
        (0..names_len(fb)).any(|j| {
            // SAFETY: as above.
            let genb = unsafe { OPENSSL_sk_value(fb.cast(), j) }.cast::<GENERAL_NAME>();
            // SAFETY: live names.
            unsafe { GENERAL_NAME_cmp(gena, genb) == 0 }
        })
    })
}

/// `crldp_check_crlissuer`: whether the distribution point's CRL issuer issued the CRL (with
/// none, whether the CRL's issuer name is the certificate's).
///
/// # Safety
/// `crl` is a live CRL.
unsafe fn crldp_check_crlissuer(dp: &DIST_POINT, crl: *mut X509_CRL, crl_score: c_int) -> bool {
    if dp.CRLissuer.is_null() {
        return crl_score & SCORE_ISSUER_NAME != 0;
    }
    // SAFETY: the caller's guarantee.
    let Some(cr) = (unsafe { crl_ref(crl) }) else {
        return false;
    };
    let nm = cr.crl.issuer;
    (0..names_len(dp.CRLissuer)).any(|i| {
        name_at(dp.CRLissuer, i).and_then(dirname).is_some_and(|d| {
            // SAFETY: the names.
            unsafe { X509_NAME_cmp(d, nm) == 0 }
        })
    })
}

/// `crl_crldp_check`: whether `x` is within the CRL's scope (its issuing distribution point
/// against the certificate's distribution points), with the reasons it covers.
///
/// # Safety
/// `x` is a live certificate; `crl` is a live CRL.
unsafe fn crl_crldp_check(
    x: *mut X509,
    crl: *mut X509_CRL,
    crl_score: c_int,
    preasons: &mut c_uint,
) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(cr) = (unsafe { crl_ref(crl) }) else {
        return false;
    };
    // Attribute certificate CRLs aren't for certificates.
    if cr.idp_flags & IDP_ONLYATTR != 0 {
        return false;
    }
    // SAFETY: as above.
    let view = unsafe { cache_view(x) };
    let only = if view.flags & ex(EXFLAG_CA) != 0 {
        IDP_ONLYUSER
    } else {
        IDP_ONLYCA
    };
    if cr.idp_flags & only != 0 {
        return false;
    }
    *preasons = cr.idp_reasons.cast_unsigned();
    // SAFETY: the CRL's issuing distribution point, or NULL.
    let idp = unsafe { cr.idp.as_ref() };
    // SAFETY: the certificate's distribution points, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(view.crldp.cast()) } {
        // SAFETY: an index within them.
        let dp = unsafe { OPENSSL_sk_value(view.crldp.cast(), i) }.cast::<DIST_POINT>();
        // SAFETY: a live distribution point.
        let Some(dp) = (unsafe { dp.as_ref() }) else {
            continue;
        };
        // SAFETY: the caller's CRL.
        if !unsafe { crldp_check_crlissuer(dp, crl, crl_score) } {
            continue;
        }
        let matched = match idp {
            None => true,
            Some(idp) => {
                let mut dpname = ptr::null_mut();
                // SAFETY: the distribution point's name, or NULL.
                if unsafe { dp.distpoint.as_ref() }.is_some_and(|n| n.type_ == 1) {
                    // SAFETY: the caller's certificate; a relative name.
                    dpname = unsafe { crldp_full_name(x, dp) };
                    if dpname.is_null() {
                        continue;
                    }
                }
                // SAFETY: the names, or NULL.
                let m = unsafe { idp_check_dp(dp.distpoint, dpname, idp.distpoint) };
                // SAFETY: made above, or NULL.
                unsafe { X509_NAME_free(dpname) };
                m
            }
        };
        if matched {
            *preasons &= dp.dp_reasons.cast_unsigned();
            return true;
        }
    }
    idp.is_none_or(|idp| idp.distpoint.is_null()) && crl_score & SCORE_ISSUER_NAME != 0
}

/// `get_crl_delta`: the best CRL for `x` (and its delta CRL), from the context's CRLs and
/// then, unless one of those is probably valid, the store's: 1 (setting the current issuer,
/// score, and reasons), or 0 for none.
///
/// # Safety
/// `ctx` is a live context; `*pcrl` and `*pdcrl` are NULL; `x` is a live certificate.
unsafe fn get_crl_delta(
    ctx: *mut X509_STORE_CTX,
    pcrl: &mut *mut X509_CRL,
    pdcrl: &mut *mut X509_CRL,
    x: *mut X509,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { cx(ctx) }) else {
        return 0;
    };
    let mut issuer = ptr::null_mut();
    let mut crl_score = 0;
    let mut reasons = c.current_reasons;
    let mut crl: *mut X509_CRL = ptr::null_mut();
    let mut dcrl: *mut X509_CRL = ptr::null_mut();
    let (crls, lookup_crls) = (c.crls, c.lookup_crls);
    // SAFETY: the context; its CRLs.
    let ok = unsafe {
        get_crl_sk(
            ctx,
            &mut crl,
            &mut dcrl,
            &mut issuer,
            &mut crl_score,
            &mut reasons,
            crls,
        )
    };
    if ok == 0 {
        // SAFETY: the certificate's issuer.
        let nm = unsafe { X509_get_issuer_name(x) };
        // SAFETY: the context's function, with no reference into it held.
        let skcrl = lookup_crls.map_or(ptr::null_mut(), |f| unsafe { f(ctx, nm) });
        if !(skcrl.is_null() && !crl.is_null()) {
            // SAFETY: the context; the store's CRLs, or NULL.
            unsafe {
                get_crl_sk(
                    ctx,
                    &mut crl,
                    &mut dcrl,
                    &mut issuer,
                    &mut crl_score,
                    &mut reasons,
                    skcrl,
                )
            };
            // SAFETY: the lookup's list, with a reference to each.
            unsafe { OPENSSL_sk_pop_free(skcrl.cast(), Some(crl_free)) };
        }
    }
    if crl.is_null() {
        return 0;
    }
    // SAFETY: as above.
    let Some(c) = (unsafe { cx(ctx) }) else {
        // SAFETY: the references taken above.
        unsafe { X509_CRL_free(crl) };
        // SAFETY: as above.
        unsafe { X509_CRL_free(dcrl) };
        return 0;
    };
    c.current_issuer = issuer;
    c.current_crl_score = crl_score;
    c.current_reasons = reasons;
    *pcrl = crl;
    *pdcrl = dcrl;
    1
}

/// `check_crl`: checks the CRL (for the certificate at the error depth): its issuer's key
/// usage, its scope, the issuer's path, its extensions, its times, Suite B, and its
/// signature, each failure going to the callback. A NULL CRL, which OpenSSL reads through,
/// fails (docs/DEVIATIONS.md).
pub(crate) unsafe extern "C" fn check_crl(ctx: *mut X509_STORE_CTX, crl: *mut X509_CRL) -> c_int {
    crate::ffi::guard(
        ERR_LIB_X509,
        "check_crl",
        || 0,
        // SAFETY: the context the verification is called with; its CRL.
        move || unsafe { check_crl_inner(ctx, crl) },
    )
}

/// [`check_crl`]'s body.
///
/// # Safety
/// `ctx` is a live context; `crl` is NULL or a live CRL.
unsafe fn check_crl_inner(ctx: *mut X509_STORE_CTX, crl: *mut X509_CRL) -> c_int {
    // SAFETY: the caller's guarantee.
    let (Some(c), Some(cr)) = (unsafe { cx(ctx) }, unsafe { crl_ref(crl) }) else {
        return 0;
    };
    let (is_delta, idp_flags) = (!cr.base_crl_number.is_null(), cr.idp_flags);
    let cnum = c.error_depth;
    let chnum = len(c.chain) - 1;
    let (current_issuer, check_issued, flags) = (c.current_issuer, c.check_issued, flags_of(c));
    // SAFETY: the caller's context.
    let rejects = |err| unsafe { verify_cb_crl(ctx, err) } == 0;
    let issuer = if !current_issuer.is_null() {
        current_issuer
    } else if cnum < chnum {
        at(c.chain, cnum + 1)
    } else {
        // The root issued the CRL, if it issued itself.
        let issuer = at(c.chain, chnum);
        if issuer.is_null() {
            return 0;
        }
        // SAFETY: the context's function, with no reference into it held.
        let issued = check_issued.map_or(0, |f| unsafe { f(ctx, issuer, issuer) });
        if issued == 0 && rejects(X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER) {
            return 0;
        }
        issuer
    };
    if issuer.is_null() {
        return 1;
    }
    // Not for delta CRLs, checked as their base's were.
    if !is_delta {
        // SAFETY: a live certificate.
        let view = unsafe { cache_view(issuer) };
        if view.flags & ex(EXFLAG_KUSAGE) != 0
            && view.kusage & ex(KU_CRL_SIGN) == 0
            && rejects(X509_V_ERR_KEYUSAGE_NO_CRL_SIGN)
        {
            return 0;
        }
        // SAFETY: as above.
        let score = unsafe { cx(ctx) }.map_or(0, |c| c.current_crl_score);
        if score & SCORE_SCOPE == 0 && rejects(X509_V_ERR_DIFFERENT_CRL_SCOPE) {
            return 0;
        }
        if score & SCORE_SAME_PATH == 0 {
            // SAFETY: as above.
            let current_issuer = unsafe { cx(ctx) }.map_or(ptr::null_mut(), |c| c.current_issuer);
            // SAFETY: the context; its current issuer, or NULL.
            if unsafe { check_crl_path(ctx, current_issuer) } <= 0
                && rejects(X509_V_ERR_CRL_PATH_VALIDATION_ERROR)
            {
                return 0;
            }
        }
        if idp_flags & IDP_INVALID != 0 && rejects(X509_V_ERR_INVALID_EXTENSION) {
            return 0;
        }
    }
    // SAFETY: as above.
    let score = unsafe { cx(ctx) }.map_or(0, |c| c.current_crl_score);
    // SAFETY: the context; the CRL.
    if score & SCORE_TIME == 0 && unsafe { check_crl_time(ctx, crl, true) } == 0 {
        return 0;
    }
    // SAFETY: a live certificate.
    let ikey = unsafe { X509_get0_pubkey(issuer) };
    if ikey.is_null() {
        if rejects(X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY) {
            return 0;
        }
    } else {
        // SAFETY: the CRL; its issuer's key.
        let rv = unsafe { X509_CRL_check_suiteb(crl, ikey, flags) };
        if rv != X509_V_OK && rejects(rv) {
            return 0;
        }
        // SAFETY: as above.
        if unsafe { X509_CRL_verify(crl, ikey) } <= 0 && rejects(X509_V_ERR_CRL_SIGNATURE_FAILURE) {
            return 0;
        }
    }
    1
}

/// `cert_crl`: looks `x` up in the CRL (after refusing unhandled critical extensions unless
/// `X509_V_FLAG_IGNORE_CRITICAL`): 2 if it's to be removed from the CRL (in a delta CRL), 0 if
/// it's revoked and the callback agrees, else 1. A NULL CRL, which OpenSSL reads through,
/// fails (docs/DEVIATIONS.md).
pub(crate) unsafe extern "C" fn cert_crl(
    ctx: *mut X509_STORE_CTX,
    crl: *mut X509_CRL,
    x: *mut X509,
) -> c_int {
    crate::ffi::guard(
        ERR_LIB_X509,
        "cert_crl",
        || 0,
        move || {
            // SAFETY: the context the verification is called with; its CRL.
            let (Some(c), Some(cr)) = (unsafe { cx(ctx) }, unsafe { crl_ref(crl) }) else {
                return 0;
            };
            if flags_of(c) & flag(X509_V_FLAG_IGNORE_CRITICAL) == 0
                && cr.flags & EXFLAG_CRITICAL != 0
                // SAFETY: as above.
                && unsafe { verify_cb_crl(ctx, X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION) } == 0
            {
                return 0;
            }
            let mut rev: *mut X509_REVOKED = ptr::null_mut();
            // SAFETY: the CRL; the certificate.
            if unsafe { X509_CRL_get0_by_cert(crl, &raw mut rev, x) } != 0 {
                // SAFETY: the CRL's entry.
                if unsafe { revoked_of(rev) }
                    .is_some_and(|r| r.reason == CRL_REASON_REMOVE_FROM_CRL)
                {
                    return 2;
                }
                // SAFETY: as above.
                if unsafe { verify_cb_crl(ctx, X509_V_ERR_CERT_REVOKED) } == 0 {
                    return 0;
                }
            }
            1
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: the default CRL checks, given a NULL CRL (which OpenSSL reads
    /// through), fail.
    #[test]
    fn null_crls_fail() {
        // SAFETY: a new context, freed below.
        let ctx = unsafe { X509_STORE_CTX_new_ex(ptr::null_mut(), ptr::null()) };
        assert!(!ctx.is_null());
        // SAFETY: the context; NULL where OpenSSL dereferences it.
        assert_eq!(unsafe { check_crl(ctx, ptr::null_mut()) }, 0);
        // SAFETY: as above.
        let r = unsafe { cert_crl(ctx, ptr::null_mut(), ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: made above.
        unsafe { X509_STORE_CTX_free(ctx) };
    }
}
