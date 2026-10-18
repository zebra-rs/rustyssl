//! The handshake's configuration from the connection and its context: what OpenSSL's state
//! machine reads from `SSL_CONNECTION` and `SSL_CTX` as it goes, copied into the core's
//! `Config` when a handshake starts.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    EVP_PKEY, EXFLAG_KUSAGE, KU_DIGITAL_SIGNATURE, NID_undef, OSSL_LIB_CTX, SSL,
    SSL_MODE_NO_AUTO_CHAIN, X509, X509_NAME, X509_STORE, stack_st_X509, stack_st_X509_NAME,
};
use rustyssl_tls::conn::{Callbacks, CertKey, Config};
use rustyssl_tls::crypto::Provider;

use super::super::conn::{Ssl, ctx_of};
use super::super::ctx::Ctx;
use super::super::tls_provider::EvpProvider;
use super::super::types::{AnyCb, AppVerifyCb, ClientCertCb, InfoCb};
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_is_a, EVP_PKEY_up_ref};
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::cert::{X509_free, X509_get0_pubkey, X509_up_ref, i2d_X509};

/// The context's pieces the driver reads, copied out under its lock.
pub(crate) struct CtxSnapshot {
    pub(crate) info_callback: InfoCb,
    pub(crate) keylog_callback: rustyssl_abi::SSL_CTX_keylog_cb_func,
    pub(crate) servername_cb: AnyCb,
    pub(crate) servername_arg: *mut c_void,
    pub(crate) alpn_select_cb: rustyssl_abi::SSL_CTX_alpn_select_cb_func,
    pub(crate) alpn_select_cb_arg: *mut c_void,
    pub(crate) client_hello_cb: rustyssl_abi::SSL_client_hello_cb_fn,
    pub(crate) client_hello_cb_arg: *mut c_void,
    pub(crate) client_cert_cb: ClientCertCb,
    pub(crate) app_verify_callback: AppVerifyCb,
    pub(crate) app_verify_arg: *mut c_void,
    pub(crate) status_cb: AnyCb,
    pub(crate) status_arg: *mut c_void,
    pub(crate) cert_store: *mut X509_STORE,
    pub(crate) extra_certs: *mut stack_st_X509,
    pub(crate) ca_names: *mut stack_st_X509_NAME,
    pub(crate) client_ca_names: *mut stack_st_X509_NAME,
    pub(crate) libctx: *mut OSSL_LIB_CTX,
    pub(crate) propq: Option<CString>,
}

impl CtxSnapshot {
    /// The property query, or NULL.
    pub(crate) fn propq(&self) -> *const c_char {
        self.propq.as_ref().map_or(ptr::null(), |q| q.as_ptr())
    }
}

/// Copies the context's pieces the driver reads.
pub(crate) fn ctx_snapshot(c: &Ctx) -> CtxSnapshot {
    let cs = c.state();
    CtxSnapshot {
        info_callback: cs.info_callback,
        keylog_callback: cs.keylog_callback,
        servername_cb: cs.servername_cb,
        servername_arg: cs.servername_arg,
        alpn_select_cb: cs.alpn_select_cb,
        alpn_select_cb_arg: cs.alpn_select_cb_arg,
        client_hello_cb: cs.client_hello_cb,
        client_hello_cb_arg: cs.client_hello_cb_arg,
        client_cert_cb: cs.client_cert_cb,
        app_verify_callback: cs.app_verify_callback,
        app_verify_arg: cs.app_verify_arg,
        status_cb: cs.status_cb,
        status_arg: cs.status_arg,
        cert_store: cs.cert_store,
        extra_certs: cs.extra_certs,
        ca_names: cs.ca_names,
        client_ca_names: cs.client_ca_names,
        libctx: c.libctx,
        propq: c.propq.clone(),
    }
}

/// The connection's context, copied out (`None` without one).
pub(crate) fn snapshot(x: &Ssl) -> Option<CtxSnapshot> {
    let st = x.state();
    // SAFETY: the connection's reference keeps its context alive.
    let c = unsafe { ctx_of(&st) }?;
    drop(st);
    Some(ctx_snapshot(c))
}

/// The authentication algorithm of a certificate slot (`ssl_cert_info`'s `amask`).
fn slot_auth(slot: usize) -> u32 {
    use rustyssl_tls::suites::masks::{SSL_aDSS, SSL_aECDSA, SSL_aGOST01, SSL_aGOST12, SSL_aRSA};
    match slot {
        0 | 1 => SSL_aRSA,
        2 => SSL_aDSS,
        3 | 7 | 8 => SSL_aECDSA,
        4 => SSL_aGOST01,
        5 | 6 => SSL_aGOST12,
        _ => 0,
    }
}

/// A slot's certificate, key, and configured chain, with references taken (so they are used
/// with no lock held).
pub(crate) struct SlotRefs {
    slot: usize,
    x509: *mut X509,
    pkey: *mut EVP_PKEY,
    /// The slot's own chain, or `None` when it has none (`cpk->chain == NULL`).
    chain: Option<Vec<*mut X509>>,
}

impl Drop for SlotRefs {
    fn drop(&mut self) {
        // SAFETY: the references taken when the slot was copied.
        unsafe { X509_free(self.x509) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(self.pkey) };
        for c in self.chain.iter().flatten() {
            // SAFETY: as above.
            unsafe { X509_free(*c) };
        }
    }
}

/// The certificates of a stack, with references taken.
///
/// # Safety
/// `sk` is NULL or a live stack of certificates.
unsafe fn refs_of(sk: *const stack_st_X509) -> Vec<*mut X509> {
    // SAFETY: the caller's stack, or NULL (-1).
    let n = unsafe { OPENSSL_sk_num(sk.cast()) };
    let mut v = Vec::new();
    for i in 0..n.max(0) {
        // SAFETY: an index in range.
        let x: *mut X509 = unsafe { OPENSSL_sk_value(sk.cast(), i) }.cast();
        // SAFETY: a certificate of the stack.
        if !x.is_null() && unsafe { X509_up_ref(x) } != 0 {
            v.push(x);
        }
    }
    v
}

/// The DER of a certificate.
///
/// # Safety
/// `x` is a live certificate.
pub(crate) unsafe fn der_of(x: *mut X509) -> Option<Vec<u8>> {
    let mut p: *mut u8 = ptr::null_mut();
    // SAFETY: the caller's certificate; a slot for the encoding.
    let n = unsafe { i2d_X509(x, &raw mut p) };
    let len = usize::try_from(n).ok().filter(|_| !p.is_null())?;
    // SAFETY: the `len` octets i2d wrote.
    let v = unsafe { core::slice::from_raw_parts(p, len) }.to_vec();
    // SAFETY: the encoding, ours.
    unsafe { crate::mem::release(p.cast()) };
    Some(v)
}

/// Where a leaf's chain comes from (`ssl_add_cert_chain`'s inputs).
struct ChainSource {
    extra: *mut stack_st_X509,
    mode: u32,
    chain_store: *mut X509_STORE,
    ctx_store: *mut X509_STORE,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
}

/// The chain `ssl_add_cert_chain` sends, leaf first: the slot's chain, else the context's
/// extra certificates, else (unless `SSL_MODE_NO_AUTO_CHAIN`) what the chain store (or the
/// context's store) builds, root included if it finds one. Built with no lock held: the
/// store's verification callback may run.
///
/// # Safety
/// The pointers in `src` are live (or NULL where allowed).
unsafe fn send_chain(r: &SlotRefs, src: &ChainSource) -> Vec<Vec<u8>> {
    use crate::x509::ctx::{
        X509_STORE_CTX_free, X509_STORE_CTX_get0_chain, X509_STORE_CTX_init, X509_STORE_CTX_new_ex,
    };
    let mut out = Vec::new();
    // SAFETY: our reference.
    let Some(leaf) = (unsafe { der_of(r.x509) }) else {
        return out;
    };
    if let Some(chain) = &r.chain {
        out.push(leaf);
        for &c in chain {
            // SAFETY: our references.
            out.extend(unsafe { der_of(c) });
        }
        return out;
    }
    if !src.extra.is_null() {
        out.push(leaf);
        // SAFETY: the context's stack.
        let v = unsafe { refs_of(src.extra) };
        for c in v {
            // SAFETY: the references taken above.
            out.extend(unsafe { der_of(c) });
            // SAFETY: as above, released once.
            unsafe { X509_free(c) };
        }
        return out;
    }
    let store = if src.mode & SSL_MODE_NO_AUTO_CHAIN != 0 {
        ptr::null_mut()
    } else if src.chain_store.is_null() {
        src.ctx_store
    } else {
        src.chain_store
    };
    if store.is_null() {
        out.push(leaf);
        return out;
    }
    // SAFETY: the library context and property query of the connection's context.
    let xs = unsafe { X509_STORE_CTX_new_ex(src.libctx, src.propq) };
    // SAFETY: the new context, the store, our leaf.
    if xs.is_null() || unsafe { X509_STORE_CTX_init(xs, store, r.x509, ptr::null_mut()) } == 0 {
        // SAFETY: made above, or NULL.
        unsafe { X509_STORE_CTX_free(xs) };
        out.push(leaf);
        return out;
    }
    // The chain needn't be complete (the root usually isn't known): the result is ignored and
    // the errors cleared, as OpenSSL does.
    // SAFETY: the initialized context; no lock is held.
    unsafe { crate::x509::verify::X509_verify_cert(xs) };
    // SAFETY: no preconditions.
    unsafe { crate::err::ERR_clear_error() };
    // SAFETY: the context.
    let chain = unsafe { X509_STORE_CTX_get0_chain(xs) };
    // SAFETY: the chain, or NULL (-1).
    let n = unsafe { OPENSSL_sk_num(chain.cast()) };
    if n <= 0 {
        out.push(leaf);
    }
    for i in 0..n.max(0) {
        // SAFETY: an index in range.
        let x: *mut X509 = unsafe { OPENSSL_sk_value(chain.cast(), i) }.cast();
        if !x.is_null() {
            // SAFETY: a certificate of the chain.
            out.extend(unsafe { der_of(x) });
        }
    }
    // SAFETY: made above.
    unsafe { X509_STORE_CTX_free(xs) };
    out
}

/// An EC key's curve as a NID (`ssl_get_EC_curve_nid`), or `NID_undef`.
///
/// # Safety
/// `pkey` is a live key.
pub(crate) unsafe fn curve_nid(pkey: *const EVP_PKEY) -> c_int {
    // SAFETY: the caller's key; a NUL-terminated name.
    if unsafe { EVP_PKEY_is_a(pkey, c"EC".as_ptr()) } == 0 {
        return NID_undef;
    }
    let mut name = [0 as c_char; 80];
    let mut len = 0usize;
    // SAFETY: as above; the room.
    let got = unsafe {
        crate::evp::pkey::params::EVP_PKEY_get_group_name(pkey, name.as_mut_ptr(), name.len(), &raw mut len)
    };
    if got == 0 {
        return NID_undef;
    }
    // SAFETY: the name written, NUL-terminated.
    let nid = unsafe { crate::objects::OBJ_sn2nid(name.as_ptr()) };
    if nid != NID_undef {
        return nid;
    }
    // SAFETY: as above.
    unsafe { crate::objects::OBJ_txt2nid(name.as_ptr()) }
}

/// A group's NID from its code point (`tls1_group_id2nid` with `include_unknown`): the
/// providers' group's curve or algorithm name as a NID, else `TLSEXT_nid_unknown | id`.
pub(crate) fn group_nid(prov: &EvpProvider, id: u16) -> c_int {
    let unknown = rustyssl_abi::TLSEXT_nid_unknown | c_int::from(id);
    let Some(g) = prov.groups().into_iter().find(|g| g.id == id) else {
        return unknown;
    };
    if g.internal_name.is_empty() {
        return unknown;
    }
    let Ok(n) = CString::new(g.internal_name) else {
        return unknown;
    };
    // SAFETY: a NUL-terminated name.
    let nid = unsafe { crate::objects::OBJ_sn2nid(n.as_ptr()) };
    if nid != NID_undef {
        return nid;
    }
    // SAFETY: as above.
    let nid = unsafe { crate::objects::OBJ_ln2nid(n.as_ptr()) };
    if nid == NID_undef { unknown } else { nid }
}

/// A group's code point by the NID of its curve, from the providers' groups.
fn group_of_nid(prov: &EvpProvider, nid: c_int) -> Option<u16> {
    if nid == NID_undef {
        return None;
    }
    prov.groups()
        .into_iter()
        .find(|g| group_nid(prov, g.id) == nid)
        .map(|g| g.id)
}

/// The `CertKey` for a slot (the work done with no lock held).
///
/// # Safety
/// The pointers in `src` are live (or NULL where allowed).
unsafe fn cert_key(prov: &EvpProvider, r: &SlotRefs, src: &ChainSource, ocsp: Option<Vec<u8>>) -> Option<CertKey> {
    // SAFETY: our reference to the key.
    let key = unsafe { prov.add_key(r.pkey) }?;
    // SAFETY: the caller's guarantee.
    let chain = unsafe { send_chain(r, src) };
    if chain.is_empty() {
        return None;
    }
    // SAFETY: our certificate; the key stays its own.
    let pub_key = unsafe { X509_get0_pubkey(r.x509) };
    // SAFETY: the certificate's key, or the slot's.
    let nid = unsafe { curve_nid(if pub_key.is_null() { r.pkey } else { pub_key }) };
    // SAFETY: our certificate.
    let ext = unsafe { crate::x509::purpose::X509_get_extension_flags(r.x509) };
    let can_sign = ext & u32::try_from(EXFLAG_KUSAGE).unwrap_or(0) == 0 || {
        // SAFETY: as above.
        let ku = unsafe { crate::x509::purpose::X509_get_key_usage(r.x509) };
        ku & u32::try_from(KU_DIGITAL_SIGNATURE).unwrap_or(0) != 0
    };
    let (mut mdnid, mut pknid) = (NID_undef, NID_undef);
    // SAFETY: as above; the slots.
    unsafe {
        crate::x509::purpose::X509_get_signature_info(
            r.x509,
            &raw mut mdnid,
            &raw mut pknid,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    Some(CertKey {
        chain,
        key,
        slot: r.slot,
        schemes: Vec::new(),
        auth: slot_auth(r.slot),
        ec_group: group_of_nid(prov, nid),
        curve_nid: nid,
        can_sign,
        cert_sig: Some((mdnid, pknid)),
        raw_public_key: None,
        ocsp_response: ocsp,
    })
}

/// The DER names of a stack of `X509_NAME`s.
///
/// # Safety
/// `sk` is NULL or a live stack of names.
unsafe fn names_der(sk: *const stack_st_X509_NAME) -> Vec<Vec<u8>> {
    // SAFETY: the caller's stack, or NULL (-1).
    let n = unsafe { OPENSSL_sk_num(sk.cast()) };
    let mut v = Vec::new();
    for i in 0..n.max(0) {
        // SAFETY: an index in range.
        let name: *mut X509_NAME = unsafe { OPENSSL_sk_value(sk.cast(), i) }.cast();
        let mut p: *mut u8 = ptr::null_mut();
        // SAFETY: a name of the stack; a slot for the encoding.
        let len = unsafe { crate::x509::name::i2d_X509_NAME(name, &raw mut p) };
        if let Ok(len) = usize::try_from(len)
            && !p.is_null()
        {
            // SAFETY: the octets written.
            v.push(unsafe { core::slice::from_raw_parts(p, len) }.to_vec());
        }
        // SAFETY: the encoding, ours, or NULL.
        unsafe { crate::mem::release(p.cast()) };
    }
    v
}

/// The connection's certificates, copied out with references taken.
fn slot_refs(x: &Ssl) -> (Vec<SlotRefs>, u32, *mut X509_STORE, Option<Vec<u8>>, usize) {
    let st = x.state();
    let mut slots = Vec::new();
    for (slot, cpk) in st.cert.pkeys.iter().enumerate() {
        if cpk.x509.is_null() || cpk.privatekey.is_null() {
            continue;
        }
        // SAFETY: the slot's certificate.
        if unsafe { X509_up_ref(cpk.x509) } == 0 {
            continue;
        }
        // SAFETY: the slot's key.
        if unsafe { EVP_PKEY_up_ref(cpk.privatekey) } == 0 {
            // SAFETY: the reference taken above.
            unsafe { X509_free(cpk.x509) };
            continue;
        }
        let chain = if cpk.chain.is_null() {
            None
        } else {
            // SAFETY: the slot's chain.
            Some(unsafe { refs_of(cpk.chain) })
        };
        slots.push(SlotRefs { slot, x509: cpk.x509, pkey: cpk.privatekey, chain });
    }
    let ocsp = if st.ocsp_resp.is_null() || st.ocsp_resp_len == 0 {
        None
    } else {
        // SAFETY: the response the connection owns, `ocsp_resp_len` octets.
        Some(unsafe { core::slice::from_raw_parts(st.ocsp_resp, st.ocsp_resp_len) }.to_vec())
    };
    (slots, st.mode, st.cert.chain_store, ocsp, st.cert.key)
}

/// The connection's certificates as the core takes them, and the current one's index.
///
/// # Safety
/// `snap` is the connection's context's snapshot.
pub(crate) unsafe fn certs(x: &Ssl, snap: &CtxSnapshot, prov: &EvpProvider) -> (Vec<CertKey>, Option<usize>) {
    let (slots, mode, chain_store, ocsp, current) = slot_refs(x);
    let src = ChainSource {
        extra: snap.extra_certs,
        mode,
        chain_store,
        ctx_store: snap.cert_store,
        libctx: snap.libctx,
        propq: snap.propq(),
    };
    let mut out = Vec::new();
    for r in &slots {
        // SAFETY: our references; the context's stores.
        if let Some(k) = unsafe { cert_key(prov, r, &src, ocsp.clone()) } {
            out.push(k);
        }
    }
    let cur = out.iter().position(|k| k.slot == current);
    (out, cur)
}

/// The handshake's configuration (`Config`) from the connection and its context.
///
/// # Safety
/// `s` is the live connection behind `x`; `snap` its context's snapshot.
pub(crate) unsafe fn build(s: *mut SSL, x: &Ssl, snap: &CtxSnapshot, prov: &EvpProvider) -> Config {
    // SAFETY: the caller's connection.
    let cipher_stack = unsafe { super::super::ciphers::ssl_ciphers(s) };
    let ciphers = super::super::ciphers::ciphers_of(cipher_stack.cast());
    // SAFETY: the connection's parameters.
    let verify_depth = unsafe { crate::x509::vpm::X509_VERIFY_PARAM_get_depth(x.param) };
    // SAFETY: the snapshot's context is alive.
    let (certs, current_cert) = unsafe { certs(x, snap, prov) };
    let st = x.state();
    let method_version = match st.method.version {
        rustyssl_abi::TLS_ANY_VERSION | rustyssl_abi::DTLS_ANY_VERSION => 0,
        v => u16::try_from(v).unwrap_or(0),
    };
    let names = if st.server {
        [st.client_ca_names, snap.client_ca_names, st.ca_names, snap.ca_names]
            .into_iter()
            .find(|p| !p.is_null())
    } else {
        [st.ca_names, snap.ca_names].into_iter().find(|p| !p.is_null())
    };
    let ca_names = match names {
        // SAFETY: the connection's or context's names (no callbacks run while encoding).
        Some(n) => unsafe { names_der(n) },
        None => Vec::new(),
    };
    Config {
        server: st.server,
        method_version,
        min_version: u16::try_from(st.min_proto_version).unwrap_or(0),
        max_version: u16::try_from(st.max_proto_version).unwrap_or(0),
        options: st.options,
        mode: u64::from(st.mode),
        verify_mode: st.verify_mode,
        ciphers,
        security_level: st.cert.sec_level,
        custom_security_callback: false,
        certs,
        current_cert,
        hostname: st.hostname.as_ref().map(|h| h.as_bytes().to_vec()),
        alpn: st.alpn.clone(),
        sid_ctx: st.sid_ctx.clone(),
        num_tickets: st.num_tickets,
        max_early_data: st.max_early_data,
        recv_max_early_data: st.recv_max_early_data,
        max_fragment_len_mode: st.max_fragment_len_mode,
        max_send_fragment: st.max_send_fragment,
        split_send_fragment: st.split_send_fragment,
        block_padding: (st.block_padding, st.hs_padding),
        max_cert_list: st.max_cert_list,
        verify_depth,
        post_handshake_auth: st.pha_enabled != 0,
        status_request: st.status_type == rustyssl_abi::TLSEXT_STATUSTYPE_ocsp,
        send_ca_names: !ca_names.is_empty(),
        ca_names,
        cert_flags: st.cert.cert_flags,
        dh_tmp: !st.cert.dh_tmp.is_null() || st.cert.dh_tmp_cb.is_some() || st.cert.dh_tmp_auto != 0,
        callbacks: Callbacks {
            info: st.info_callback.is_some() || snap.info_callback.is_some(),
            msg: st.msg_callback.is_some(),
            keylog: snap.keylog_callback.is_some(),
            servername: snap.servername_cb.is_some(),
            client_hello: snap.client_hello_cb.is_some(),
            cert: st.cert.cert_cb.is_some(),
            client_cert: snap.client_cert_cb.is_some(),
            alpn_select: snap.alpn_select_cb.is_some(),
            status: snap.status_cb.is_some(),
            record_padding: st.record_padding_cb.is_some(),
            allow_early_data: st.allow_early_data_cb.is_some(),
            ..Callbacks::default()
        },
        ..Config::default()
    }
}
