//! `SSL_check_chain`: whether a certificate, its key, and a chain suit the handshake so far
//! (`tls1_check_chain` with `idx == -1`), the work done by the core on what this module reads
//! from the objects.

use core::ffi::{c_int, c_uchar};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_SSL, EVP_PKEY, NID_undef, SSL, TLS_CT_DSS_SIGN, TLS_CT_ECDSA_SIGN, TLS_CT_RSA_SIGN,
    X509, stack_st_X509,
};
use rustyssl_tls::conn::common::sigalgs::{ChainCandidate, ChainCert, check_chain};

use super::conn::ssl;
use super::tls_provider::EvpProvider;
use crate::evp::pkey::EVP_PKEY_is_a;
use crate::ffi::ffi_export;
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::cert::{X509_get_issuer_name, X509_get_signature_nid, X509_get0_pubkey};
use crate::x509::purpose::{X509_get_signature_info, X509_self_signed};

/// The DER of a name, or nothing.
///
/// # Safety
/// `name` is NULL or a live name.
unsafe fn name_der(name: *mut rustyssl_abi::X509_NAME) -> Vec<u8> {
    if name.is_null() {
        return Vec::new();
    }
    let mut p: *mut c_uchar = ptr::null_mut();
    // SAFETY: the caller's name; our slot for the encoding.
    let len = unsafe { crate::x509::name::i2d_X509_NAME(name, &raw mut p) };
    let Ok(n) = usize::try_from(len) else {
        return Vec::new();
    };
    if p.is_null() {
        return Vec::new();
    }
    // SAFETY: the encoding's `n` octets.
    let v = unsafe { core::slice::from_raw_parts(p, n) }.to_vec();
    // SAFETY: the encoding, from `CRYPTO_malloc`.
    unsafe { crate::mem::release(p.cast()) };
    v
}

/// What the core needs of one certificate.
///
/// # Safety
/// `x` is a live certificate.
unsafe fn cert_of(prov: Option<&EvpProvider>, x: *mut X509) -> ChainCert {
    // SAFETY: the caller's certificate.
    let sig_nid = unsafe { X509_get_signature_nid(x) };
    let (mut md, mut pk) = (NID_undef, NID_undef);
    // SAFETY: a NID; our slots.
    let found =
        unsafe { crate::objects::sigid::OBJ_find_sigid_algs(sig_nid, &raw mut md, &raw mut pk) }
            != 0;
    // SAFETY: the caller's certificate.
    let self_signed = unsafe { X509_self_signed(x, 0) } == 1;
    // SAFETY: as above.
    let name = unsafe { X509_get_issuer_name(x) };
    // SAFETY: the certificate's issuer name.
    let issuer = unsafe { name_der(name) };
    // SAFETY: as above.
    let key = unsafe { X509_get0_pubkey(x) };
    // SAFETY: the certificate's key; a NUL-terminated name.
    let ec = !key.is_null() && unsafe { EVP_PKEY_is_a(key, c"EC".as_ptr()) } != 0;
    let ec_group = ec.then(|| {
        // SAFETY: as above.
        let nid = unsafe { super::io::config::curve_nid(key) };
        prov.and_then(|p| super::io::config::group_of_nid(p, nid))
            .unwrap_or(0)
    });
    ChainCert {
        sig_nid,
        sig_algs: found.then_some((md, pk)),
        self_signed,
        issuer,
        has_key: !key.is_null(),
        ec_group,
    }
}

/// The key's `TLS_CT_*` signing type, or 0.
///
/// # Safety
/// `pk` is a live key.
unsafe fn cert_type(pk: *const EVP_PKEY) -> u8 {
    for (name, ct) in [
        (c"RSA", TLS_CT_RSA_SIGN),
        (c"DSA", TLS_CT_DSS_SIGN),
        (c"EC", TLS_CT_ECDSA_SIGN),
    ] {
        // SAFETY: the caller's key; a static name.
        if unsafe { EVP_PKEY_is_a(pk, name.as_ptr()) } != 0 {
            return u8::try_from(ct).unwrap_or(0);
        }
    }
    0
}

ffi_export! {
    /// The `CERT_PKEY_*` flags of `x` with `pk` and `chain` for the connection's handshake
    /// (`CERT_PKEY_VALID` when usable); 0 for a NULL certificate or key, or a key of no slot.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `x`, `pk` NULL or live; `chain` NULL or a live stack
    /// of certificates.
    pub unsafe extern "C" fn rustyssl_private_SSL_check_chain(s: *mut SSL, x: *mut X509, pk: *mut EVP_PKEY, chain: *mut stack_st_X509) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ssl(s) }) else { return 0 };
        if x.is_null() || pk.is_null() {
            return 0;
        }
        // SAFETY: the caller's key.
        let Some(slot) = (unsafe { super::cert::lookup_by_pkey(pk) }) else { return 0 };
        // SAFETY: the caller's connection.
        if !unsafe { super::io::ensure_core(s, c) } {
            return 0;
        }
        let prov = c.state().drv.provider.clone();
        let prov = prov.as_deref();
        // SAFETY: the caller's certificate.
        let leaf = unsafe { cert_of(prov, x) };
        let mut rest = Vec::new();
        // SAFETY: the caller's stack, or NULL (-1).
        let n = unsafe { OPENSSL_sk_num(chain.cast()) };
        for i in 0..n.max(0) {
            // SAFETY: an index in range.
            let y: *mut X509 = unsafe { OPENSSL_sk_value(chain.cast(), i) }.cast();
            if !y.is_null() {
                // SAFETY: a certificate of the stack.
                rest.push(unsafe { cert_of(prov, y) });
            }
        }
        let (mut md, mut pknid) = (NID_undef, NID_undef);
        // SAFETY: the caller's certificate; our slots.
        let info = unsafe {
            X509_get_signature_info(x, &raw mut md, &raw mut pknid, ptr::null_mut(), ptr::null_mut())
        } != 0;
        let cand = ChainCandidate {
            leaf,
            chain: rest,
            slot: Some(slot),
            // SAFETY: the caller's key.
            cert_type: unsafe { cert_type(pk) },
            // SAFETY: as above.
            curve_nid: unsafe { super::io::config::curve_nid(pk) },
            sig_info: info.then_some((md, pknid)),
        };
        let st = c.state();
        let Some(core) = st.drv.tls.as_deref() else { return 0 };
        c_int::try_from(check_chain(core, &cand)).unwrap_or(0)
    }
}
