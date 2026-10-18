//! Protecting CMP messages (`cmp_protect.c`): the protection computed over the header and
//! body, by password-based MAC or by signature; the protection algorithm and sender key ID set
//! from the context's credentials; and the extra certificates sent along (the signer's chain,
//! then the context's `extraCertsOut`).

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_OBJECT, ASN1_OCTET_STRING, ASN1_STRING, ASN1_STRING_FLAG_BITS_LEFT,
    CMP_R_CERT_AND_KEY_DO_NOT_MATCH, CMP_R_ERROR_CALCULATING_PROTECTION,
    CMP_R_ERROR_PROTECTING_MESSAGE, CMP_R_MISSING_KEY_INPUT_FOR_CREATING_PROTECTION,
    CMP_R_MISSING_PBM_SECRET, CMP_R_MISSING_SENDER_IDENTIFICATION, CMP_R_UNKNOWN_ALGORITHM_ID,
    CMP_R_WRONG_ALGORITHM_OID, ERR_LIB_CMP, NID_id_PasswordBasedMAC, OSSL_CMP_CTX,
    OSSL_CMP_LOG_DEBUG, OSSL_CMP_LOG_WARNING, OSSL_CMP_MSG, OSSL_CRMF_PBMPARAMETER,
    V_ASN1_SEQUENCE, X509, X509_ADD_FLAG_NO_DUP, X509_ADD_FLAG_NO_SS, X509_ADD_FLAG_PREPEND,
    X509_ADD_FLAG_UP_REF, X509_ALGOR,
};

use super::asn::{Msg, ProtectedPart, Stack, of, protectedpart_it};
use super::ctx::{Ctx, OSSL_CMP_CTX_print_errors, ctx_of, print_log};
use super::hdr::{general_name_is_NULL_DN, hdr_set1_senderKID};
use crate::asn1::bit_string::ASN1_BIT_STRING_set;
use crate::asn1::sign::ASN1_item_sign_ex;
use crate::asn1::string::{
    ASN1_BIT_STRING_free, ASN1_BIT_STRING_new, ASN1_STRING_free, ASN1_STRING_new, ASN1_STRING_set,
};
use crate::asn1::tpl::encode::ASN1_item_i2d;
use crate::asn1::tpl::items::{X509_ALGOR_free, X509_ALGOR_new};
use crate::crmf::asn::{
    OSSL_CRMF_PBMPARAMETER_free, d2i_OSSL_CRMF_PBMPARAMETER, i2d_OSSL_CRMF_PBMPARAMETER,
};
use crate::crmf::pbm::{OSSL_CRMF_pbm_new, OSSL_CRMF_pbmp_new};
use crate::err;
use crate::evp::digest::EVP_MD_get_type;
use crate::evp::pkey::EVP_PKEY_get_default_digest_name;
use crate::mem;
use crate::objects::OBJ_obj2nid;
use crate::ocsp::cl::add_cert_new;
use crate::rsa_pmeth::algor_from_nid;
use crate::stack::{OPENSSL_sk_free, OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::algor::X509_ALGOR_get0;
use crate::x509::cert::X509_check_private_key;
use crate::x509::purpose::X509_get0_subject_key_id;
use crate::x509::verify::X509_build_chain;

/// `ossl_asn1_string_set_bits_left`: the string's unused bits, recorded as known.
fn set_bits_left(s: &mut ASN1_BIT_STRING, num: u8) {
    s.flags &= !0x07;
    s.flags |= c_long::from(ASN1_STRING_FLAG_BITS_LEFT) | c_long::from(num & 0x07);
}

/// `ossl_x509_add_certs_new`: each of `certs` added to `*slot` (made when the first comes) with
/// `X509_add_cert`'s `flags`; with `X509_ADD_FLAG_PREPEND` in reverse, so they keep their order.
///
/// # Safety
/// `*slot` is NULL or a live list of certificates; `certs` NULL or one.
pub(crate) unsafe fn add_certs_new(
    slot: &mut *mut Stack,
    certs: *const Stack,
    flags: c_int,
) -> bool {
    // SAFETY: the caller's list, or NULL (0).
    let n = unsafe { OPENSSL_sk_num(certs) };
    for i in 0..n {
        let j = if flags & X509_ADD_FLAG_PREPEND == 0 {
            i
        } else {
            n - 1 - i
        };
        // SAFETY: an index in range.
        let cert: *mut X509 = unsafe { OPENSSL_sk_value(certs, j) }.cast();
        // SAFETY: the caller's slot; one of its certificates.
        if !unsafe { add_cert_new(slot, cert, flags) } {
            return false;
        }
    }
    true
}

/// `ossl_cmp_calc_protection`: the protection of `msg` by its header's `protectionAlg`, with
/// the context's credentials: a password-based MAC with the algorithm's parameters and the
/// context's secret, or else a signature with the context's key and digest (none for keys whose
/// default digest is "UNDEF", such as Ed25519 and Ed448), completing the algorithm. Also used to
/// check a password-based MAC. The new bit string, or NULL.
///
/// # Safety
/// `ctx` and `msg` are NULL or live.
pub(crate) unsafe fn calc_protection(
    ctx: *const OSSL_CMP_CTX,
    msg: *const OSSL_CMP_MSG,
) -> *mut ASN1_BIT_STRING {
    const F: &str = "ossl_cmp_calc_protection";
    // SAFETY: the caller's guarantee.
    let (Some(c), Some(m)) = (unsafe { ctx_of(ctx) }, unsafe { of::<Msg, _>(msg) }) else {
        return ptr::null_mut();
    };
    let prot_part = ProtectedPart {
        header: m.header,
        body: m.body,
    };
    // SAFETY: the message's header.
    let alg = unsafe { (*m.header).protectionAlg };
    if alg.is_null() {
        err::raise(ERR_LIB_CMP, CMP_R_UNKNOWN_ALGORITHM_ID, F);
        return ptr::null_mut();
    }
    let mut algor_oid: *const ASN1_OBJECT = ptr::null();
    let mut pptype: c_int = 0;
    let mut ppval: *const c_void = ptr::null();
    // SAFETY: rooms for the parts; the algorithm.
    unsafe { X509_ALGOR_get0(&raw mut algor_oid, &raw mut pptype, &raw mut ppval, alg) };

    // SAFETY: the algorithm's object.
    if unsafe { OBJ_obj2nid(algor_oid) } == NID_id_PasswordBasedMAC {
        // SAFETY: the context's secret, or NULL.
        let Some(secret) = (unsafe { c.secretValue.as_ref() }) else {
            err::raise(ERR_LIB_CMP, CMP_R_MISSING_PBM_SECRET, F);
            return ptr::null_mut();
        };
        if pptype != V_ASN1_SEQUENCE || ppval.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_ERROR_CALCULATING_PROTECTION, F);
            return ptr::null_mut();
        }
        // SAFETY: an unpacked SEQUENCE parameter is a string.
        let pbm_str = unsafe { &*ppval.cast::<ASN1_STRING>() };
        // SAFETY: the context's secret (CRYPTO_malloc'd data, `length` octets).
        unsafe { pbm_mac(c, &prot_part, pbm_str, secret.data, secret.length) }
    } else {
        if c.pkey.is_null() {
            err::raise(
                ERR_LIB_CMP,
                CMP_R_MISSING_KEY_INPUT_FOR_CREATING_PROTECTION,
                F,
            );
            return ptr::null_mut();
        }
        let mut md = c.digest.cast_const();
        let mut name = [0 as c_char; 80];
        // SAFETY: the key; the room.
        if unsafe { EVP_PKEY_get_default_digest_name(c.pkey, name.as_mut_ptr(), name.len()) } > 0
            // SAFETY: NUL-terminated within the room (zeroed, and the function terminates).
            && unsafe { CStr::from_ptr(name.as_ptr()) } == c"UNDEF"
        {
            md = ptr::null();
        }
        // SAFETY: no preconditions.
        let prot = unsafe { ASN1_BIT_STRING_new() };
        if prot.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let it = unsafe { protectedpart_it() };
        // SAFETY: the protected part's item and value; the header's algorithm, which this
        // completes; the new string; the context's key, digest, and library context.
        if unsafe {
            ASN1_item_sign_ex(
                it,
                alg,
                ptr::null_mut(),
                prot,
                ptr::from_ref(&prot_part).cast(),
                ptr::null(),
                c.pkey,
                md,
                c.libctx,
                c.propq,
            )
        } != 0
        {
            return prot;
        }
        // SAFETY: made above.
        unsafe { ASN1_BIT_STRING_free(prot) };
        ptr::null_mut()
    }
}

/// The password-based MAC branch of [`calc_protection`].
///
/// # Safety
/// `pbm_str` is the algorithm's parameter; `secret` points to `secret_len` octets.
unsafe fn pbm_mac(
    c: &Ctx,
    prot_part: &ProtectedPart,
    pbm_str: &ASN1_STRING,
    secret: *const u8,
    secret_len: c_int,
) -> *mut ASN1_BIT_STRING {
    const F: &str = "ossl_cmp_calc_protection";
    let mut prot: *mut ASN1_BIT_STRING = ptr::null_mut();
    let mut der: *mut u8 = ptr::null_mut();
    let mut pbm: *mut OSSL_CRMF_PBMPARAMETER = ptr::null_mut();
    let mut protection: *mut u8 = ptr::null_mut();
    'end: {
        // SAFETY: no preconditions.
        let it = unsafe { protectedpart_it() };
        // SAFETY: the protected part's value and item; the room for the encoding.
        let len = unsafe { ASN1_item_i2d(ptr::from_ref(prot_part).cast(), &raw mut der, it) };
        let Ok(der_len) = usize::try_from(len) else {
            err::raise(ERR_LIB_CMP, CMP_R_ERROR_CALCULATING_PROTECTION, F);
            break 'end;
        };
        if der.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_ERROR_CALCULATING_PROTECTION, F);
            break 'end;
        }
        let mut p = pbm_str.data.cast_const();
        // SAFETY: the parameter's `length` octets.
        pbm = unsafe {
            d2i_OSSL_CRMF_PBMPARAMETER(ptr::null_mut(), &raw mut p, c_long::from(pbm_str.length))
        };
        if pbm.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_WRONG_ALGORITHM_OID, F);
            break 'end;
        }
        let secret_len = usize::try_from(secret_len).unwrap_or(0);
        let mut sig_len = 0usize;
        // SAFETY: the context's library context and properties; the parameters; the encoding's
        // `der_len` octets; the secret; rooms for the MAC.
        if unsafe {
            OSSL_CRMF_pbm_new(
                c.libctx,
                c.propq,
                pbm,
                der,
                der_len,
                secret,
                secret_len,
                &raw mut protection,
                &raw mut sig_len,
            )
        } == 0
        {
            break 'end;
        }
        // SAFETY: no preconditions.
        prot = unsafe { ASN1_BIT_STRING_new() };
        // SAFETY: the new string, or NULL.
        let Some(s) = (unsafe { prot.as_mut() }) else {
            break 'end;
        };
        // OpenSSL encodes every bit string as a NamedBitList by default.
        set_bits_left(s, 0);
        let set = c_int::try_from(sig_len).is_ok_and(|n| {
            // SAFETY: the new string; the MAC's `n` octets.
            (unsafe { ASN1_BIT_STRING_set(prot, protection, n) }) != 0
        });
        if !set {
            // SAFETY: made above.
            unsafe { ASN1_BIT_STRING_free(prot) };
            prot = ptr::null_mut();
        }
    }
    // SAFETY: decoded above, or NULL.
    unsafe { OSSL_CRMF_PBMPARAMETER_free(pbm) };
    // SAFETY: the MAC from OSSL_CRMF_pbm_new, or NULL.
    unsafe { mem::release(protection.cast()) };
    // SAFETY: the encoding from ASN1_item_i2d, or NULL.
    unsafe { mem::release(der.cast()) };
    prot
}

/// `ossl_cmp_set_own_chain`: unless already done, the chain of the context's own certificate
/// built from its untrusted certificates (logging how that went).
///
/// # Safety
/// `ctx` is NULL or a live context.
pub(crate) unsafe fn set_own_chain(ctx: *mut OSSL_CMP_CTX) {
    const FUNC: &CStr = c"ossl_cmp_set_own_chain";
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return;
    };
    if !c.chain.is_null() {
        return;
    }
    // SAFETY: the live context.
    unsafe {
        print_log(
            OSSL_CMP_LOG_DEBUG,
            ctx,
            FUNC,
            "trying to build chain for own CMP signer cert",
        )
    };
    // SAFETY: the context's certificate and untrusted certificates (NULL or live), library
    // context, and properties.
    let chain = unsafe {
        X509_build_chain(
            c.cert,
            c.untrusted.cast(),
            ptr::null_mut(),
            0,
            c.libctx,
            c.propq,
        )
    };
    // SAFETY: as above.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return;
    };
    c.chain = chain.cast();
    if !chain.is_null() {
        // SAFETY: the live context.
        unsafe {
            print_log(
                OSSL_CMP_LOG_DEBUG,
                ctx,
                FUNC,
                "success building chain for own CMP signer cert",
            )
        };
    } else {
        // Dumped so they don't confuse what's printed after.
        // SAFETY: the live context.
        unsafe { OSSL_CMP_CTX_print_errors(ctx) };
        // SAFETY: as above.
        unsafe {
            print_log(
                OSSL_CMP_LOG_WARNING,
                ctx,
                FUNC,
                "could not build chain for own CMP signer cert",
            )
        };
    }
}

/// `ossl_cmp_msg_add_extraCerts`: for signature-based protection, the context's certificate and
/// its chain first (or just the certificate if no chain could be built), then the context's
/// `extraCertsOut`, onto the message's extra certificates (each once, with a reference); an
/// empty list is removed. 1, or 0.
///
/// # Safety
/// `ctx` and `msg` are NULL or live.
pub(crate) unsafe fn msg_add_extraCerts(ctx: *mut OSSL_CMP_CTX, msg: *mut OSSL_CMP_MSG) -> c_int {
    const FUNC: &CStr = c"ossl_cmp_msg_add_extraCerts";
    // SAFETY: the caller's guarantee.
    let (Some(c), Some(_)) = (unsafe { ctx_of(ctx) }, unsafe { of::<Msg, _>(msg) }) else {
        return 0;
    };
    if c.unprotectedSend == 0 && c.secretValue.is_null() && !c.cert.is_null() && !c.pkey.is_null() {
        let prepend = X509_ADD_FLAG_UP_REF
            | X509_ADD_FLAG_NO_DUP
            | X509_ADD_FLAG_PREPEND
            | X509_ADD_FLAG_NO_SS;
        // SAFETY: the live context.
        unsafe { set_own_chain(ctx) };
        // SAFETY: as above, after the call.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            return 0;
        };
        // SAFETY: the caller's message, borrowed for the additions.
        let Some(m) = (unsafe { of::<Msg, _>(msg) }) else {
            return 0;
        };
        if !c.chain.is_null() {
            // SAFETY: the message's list; the context's chain.
            if !unsafe { add_certs_new(&mut m.extraCerts, c.chain, prepend) } {
                return 0;
            }
        } else {
            // At least the signer's own certificate, first.
            // SAFETY: the message's list; the context's certificate.
            if !unsafe { add_cert_new(&mut m.extraCerts, c.cert, prepend) } {
                return 0;
            }
            // SAFETY: the live context.
            unsafe {
                print_log(
                    OSSL_CMP_LOG_DEBUG,
                    ctx,
                    FUNC,
                    "fallback: adding just own CMP signer cert",
                )
            };
        }
    }
    // SAFETY: as above.
    let (Some(c), Some(m)) = (unsafe { ctx_of(ctx) }, unsafe { of::<Msg, _>(msg) }) else {
        return 0;
    };
    // SAFETY: the message's list; the context's extra certificates, or NULL.
    if !unsafe {
        add_certs_new(
            &mut m.extraCerts,
            c.extraCertsOut,
            X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP,
        )
    } {
        return 0;
    }
    // No empty SEQUENCE.
    // SAFETY: the list, or NULL (0).
    if unsafe { OPENSSL_sk_num(m.extraCerts) } == 0 {
        // SAFETY: the empty list, or NULL.
        unsafe { OPENSSL_sk_free(m.extraCerts) };
        m.extraCerts = ptr::null_mut();
    }
    1
}

/// `pbmac_algor`: the PasswordBasedMac AlgorithmIdentifier with new parameters from the
/// context's settings (random salt), or NULL.
///
/// # Safety
/// `c` is a live context's.
unsafe fn pbmac_algor(c: &Ctx) -> *mut X509_ALGOR {
    // SAFETY: the context's digest, or NULL.
    let owf = unsafe { EVP_MD_get_type(c.pbm_owf) };
    // A negative count wraps to a huge size_t in C, which the function refuses.
    let itercnt = usize::try_from(c.pbm_itercnt).unwrap_or(usize::MAX);
    // SAFETY: the context's library context.
    let pbm = unsafe { OSSL_CRMF_pbmp_new(c.libctx, c.pbm_slen, owf, itercnt, c.pbm_mac) };
    // SAFETY: no preconditions.
    let pbm_str = unsafe { ASN1_STRING_new() };
    let mut der: *mut u8 = ptr::null_mut();
    let mut alg: *mut X509_ALGOR = ptr::null_mut();
    if !pbm.is_null() && !pbm_str.is_null() {
        // SAFETY: the parameters; the room for the encoding.
        let len = unsafe { i2d_OSSL_CRMF_PBMPARAMETER(pbm, &raw mut der) };
        // SAFETY: the new string; the encoding's `len` octets.
        if len >= 0 && unsafe { ASN1_STRING_set(pbm_str, der.cast(), len) } != 0 {
            // SAFETY: a SEQUENCE parameter, the string, which the identifier takes.
            alg =
                unsafe { algor_from_nid(NID_id_PasswordBasedMAC, V_ASN1_SEQUENCE, pbm_str.cast()) };
        }
    }
    if alg.is_null() {
        // SAFETY: made above, or NULL.
        unsafe { ASN1_STRING_free(pbm_str) };
    }
    // SAFETY: the encoding, or NULL.
    unsafe { mem::release(der.cast()) };
    // SAFETY: made above, or NULL.
    unsafe { OSSL_CRMF_PBMPARAMETER_free(pbm) };
    alg
}

/// `set_senderKID`: the header's senderKID as `id`, or the context's referenceValue when `id`
/// is NULL (standard for PBM, the fallback for signatures); none if both are. 1, or 0.
///
/// # Safety
/// `c` is a live context's; `m` a live message's; `id` NULL or live.
unsafe fn set_senderKID(c: &Ctx, m: &Msg, id: *const ASN1_OCTET_STRING) -> bool {
    let id = if id.is_null() {
        c.referenceValue.cast_const()
    } else {
        id
    };
    // SAFETY: the message's header; the identifier.
    id.is_null() || unsafe { hdr_set1_senderKID(m.header.cast(), id) } != 0
}

/// `ossl_cmp_msg_protect`: any earlier protection removed, then the message protected as the
/// context says: not at all (`unprotectedSend`, with any referenceValue as senderKID), by
/// password-based MAC if there is a secret, or by signature with the context's certificate
/// and matching key (its subject key ID as senderKID); then the extra certificates added. A
/// NULL-DN sender with no senderKID fails. 1, or 0 with `CMP_R_ERROR_PROTECTING_MESSAGE`.
///
/// # Safety
/// `ctx` and `msg` are NULL or live.
pub(crate) unsafe fn msg_protect(ctx: *mut OSSL_CMP_CTX, msg: *mut OSSL_CMP_MSG) -> c_int {
    const F: &str = "ossl_cmp_msg_protect";
    // SAFETY: the caller's guarantee.
    let (Some(c), Some(m)) = (unsafe { ctx_of(ctx) }, unsafe { of::<Msg, _>(msg) }) else {
        return 0;
    };
    'err: {
        // Re-protection: the old protection goes; extraCerts stay. The header is written
        // through its pointer, since the calls below change it too.
        let hp = m.header;
        // SAFETY: the message's header.
        let old = unsafe { (*hp).protectionAlg };
        // SAFETY: the header's algorithm, or NULL.
        unsafe { X509_ALGOR_free(old) };
        // SAFETY: the message's header.
        unsafe { (*hp).protectionAlg = ptr::null_mut() };
        // SAFETY: the message's protection, or NULL.
        unsafe { ASN1_BIT_STRING_free(m.protection) };
        m.protection = ptr::null_mut();

        if c.unprotectedSend != 0 {
            // SAFETY: the live context and message.
            if !unsafe { set_senderKID(c, m, ptr::null()) } {
                break 'err;
            }
        } else if !c.secretValue.is_null() {
            // SAFETY: the live context.
            let alg = unsafe { pbmac_algor(c) };
            // SAFETY: the message's header.
            unsafe { (*hp).protectionAlg = alg };
            if alg.is_null() {
                break 'err;
            }
            // SAFETY: as above.
            if !unsafe { set_senderKID(c, m, ptr::null()) } {
                break 'err;
            }
        } else if !c.cert.is_null() && !c.pkey.is_null() {
            // SAFETY: the context's certificate and key.
            if unsafe { X509_check_private_key(c.cert, c.pkey) } == 0 {
                err::raise(ERR_LIB_CMP, CMP_R_CERT_AND_KEY_DO_NOT_MATCH, F);
                break 'err;
            }
            // SAFETY: no preconditions.
            let alg = unsafe { X509_ALGOR_new() };
            // SAFETY: the message's header.
            unsafe { (*hp).protectionAlg = alg };
            if alg.is_null() {
                break 'err;
            }
            // SAFETY: the context's certificate.
            let skid = unsafe { X509_get0_subject_key_id(c.cert) };
            // SAFETY: the live context and message; the certificate's key ID, or NULL.
            if !unsafe { set_senderKID(c, m, skid) } {
                break 'err;
            }
        } else {
            err::raise(
                ERR_LIB_CMP,
                CMP_R_MISSING_KEY_INPUT_FOR_CREATING_PROTECTION,
                F,
            );
            break 'err;
        }
        if c.unprotectedSend == 0 {
            // SAFETY: the live context and message.
            let prot = unsafe { calc_protection(ctx, msg) };
            // SAFETY: as above.
            let Some(m) = (unsafe { of::<Msg, _>(msg) }) else {
                break 'err;
            };
            m.protection = prot;
            if prot.is_null() {
                break 'err;
            }
        }
        // SAFETY: as above.
        if unsafe { msg_add_extraCerts(ctx, msg) } == 0 {
            break 'err;
        }
        // RFC 9810 section 5.1.1: a NULL-DN sender must be identified by senderKID.
        // SAFETY: as above.
        let Some(m) = (unsafe { of::<Msg, _>(msg) }) else {
            break 'err;
        };
        // SAFETY: the message's header.
        let h = unsafe { &*m.header };
        // SAFETY: the header's sender, or NULL.
        if !(unsafe { general_name_is_NULL_DN(h.sender) } != 0 && h.senderKID.is_null()) {
            return 1;
        }
        err::raise(ERR_LIB_CMP, CMP_R_MISSING_SENDER_IDENTIFICATION, F);
    }
    err::raise(ERR_LIB_CMP, CMP_R_ERROR_PROTECTING_MESSAGE, F);
    0
}
