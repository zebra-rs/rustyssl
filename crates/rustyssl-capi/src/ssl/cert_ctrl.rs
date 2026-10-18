//! The ctrl commands about certificates and temporary keys (`ssl3_ctrl`, `ssl3_ctx_ctrl`,
//! `ssl_build_cert_chain`): the certificate types a TLS 1.2 CertificateRequest lists, each
//! end's temporary key, the peer's supported groups, DH parameters, and building a
//! certificate's chain from the store.

use core::ffi::{c_long, c_void};
use core::ptr;

use rustyssl_abi::{
    DH, ERR_LIB_SSL, ERR_R_DH_LIB, ERR_R_PASSED_NULL_PARAMETER, ERR_R_X509_LIB, EVP_PKEY,
    EXFLAG_SS, SSL, SSL_BUILD_CHAIN_FLAG_CHECK, SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR,
    SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR, SSL_BUILD_CHAIN_FLAG_NO_ROOT,
    SSL_BUILD_CHAIN_FLAG_UNTRUSTED, SSL_CERT_FLAG_SUITEB_128_LOS, SSL_CTRL_BUILD_CERT_CHAIN,
    SSL_CTRL_GET_CLIENT_CERT_TYPES, SSL_CTRL_GET_IANA_GROUPS, SSL_CTRL_GET_TMP_KEY,
    SSL_CTRL_SET_CLIENT_CERT_TYPES, SSL_CTRL_SET_TMP_DH, SSL_CTX, SSL_R_CERTIFICATE_VERIFY_FAILED,
    SSL_R_NO_CERTIFICATE_SET, X509, X509_STORE, stack_st_X509,
};

use super::cert::{Cert, Owner, security_cert};
use super::conn::{Ssl, ssl};
use super::ctx::ctx;
use super::io::x509_free;
use crate::err::{self, ERR_clear_error};
use crate::evp::pkey::EVP_PKEY_new;
use crate::evp::pkey::dh::EVP_PKEY_set1_DH;
use crate::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_shift, OPENSSL_sk_value,
};
use crate::x509::cert::{X509_free, X509_up_ref};
use crate::x509::ctx::{
    X509_STORE_CTX_free, X509_STORE_CTX_get_error, X509_STORE_CTX_get1_chain, X509_STORE_CTX_init,
    X509_STORE_CTX_new_ex, X509_STORE_CTX_set_flags, X509_verify_cert_error_string,
};
use crate::x509::purpose::X509_get_extension_flags;
use crate::x509::store::{X509_STORE_add_cert, X509_STORE_free, X509_STORE_up_ref};
use crate::x509::verify::X509_verify_cert;

/// `ssl3_set_req_cert_type`: the certificate types a TLS 1.2 CertificateRequest lists (none
/// for the default); 1, or 0 for more than 255.
///
/// # Safety
/// `p` is NULL or `len` readable octets.
unsafe fn set_req_cert_type(c: &mut Cert, p: *const u8, len: c_long) -> c_long {
    c.ctype = None;
    if p.is_null() || len == 0 {
        return 1;
    }
    let Ok(n) = usize::try_from(len) else {
        return 0;
    };
    if n > 0xff {
        return 0;
    }
    // SAFETY: the caller's `len` octets.
    let types = unsafe { core::slice::from_raw_parts(p, n) };
    c.ctype = Some(types.to_vec());
    1
}

/// `ssl_dh_to_pkey`, then the owner's `set0_tmp_dh_pkey`: 1, or 0.
///
/// # Safety
/// The owner is live; `dh` is NULL or a live DH key.
unsafe fn set_tmp_dh(owner: Owner, dh: *mut DH) -> c_long {
    const F: &str = "ssl3_ctrl";
    if dh.is_null() {
        err::raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER, F);
        return 0;
    }
    // SAFETY: no preconditions.
    let pkey = unsafe { EVP_PKEY_new() };
    // SAFETY: the new key (or NULL, refused); the caller's DH key, which it takes a reference to.
    if pkey.is_null() || unsafe { EVP_PKEY_set1_DH(pkey, dh) } == 0 {
        // SAFETY: made here, or NULL.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        err::raise(ERR_LIB_SSL, ERR_R_DH_LIB, F);
        return 0;
    }
    let ok = match owner {
        // SAFETY: the live context; the key, which it takes on success.
        Owner::Ctx(c) => unsafe {
            super::keys::rustyssl_private_SSL_CTX_set0_tmp_dh_pkey(c.cast_mut(), pkey)
        },
        // SAFETY: as above, the live connection.
        Owner::Ssl(s) => unsafe {
            super::keys::rustyssl_private_SSL_set0_tmp_dh_pkey(s.cast_mut(), pkey)
        },
    };
    if ok == 0 {
        // SAFETY: not taken.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        return 0;
    }
    1
}

/// What chain building needs, with references taken under the lock (used with none held).
struct ChainInputs {
    leaf: *mut X509,
    chain: Vec<*mut X509>,
    /// The store to build from (a reference held): the configuration's chain store, else the
    /// context's certificate store.
    store: *mut X509_STORE,
    cert_flags: u32,
    libctx: *mut rustyssl_abi::OSSL_LIB_CTX,
    propq: Option<std::ffi::CString>,
}

impl Drop for ChainInputs {
    fn drop(&mut self) {
        // SAFETY: the references taken when the inputs were copied.
        unsafe { X509_free(self.leaf) };
        for x in &self.chain {
            // SAFETY: as above.
            unsafe { X509_free(*x) };
        }
        // SAFETY: as above.
        unsafe { X509_STORE_free(self.store) };
    }
}

/// The current slot's certificate and chain, and the stores, with references taken.
///
/// # Safety
/// The owner is live.
unsafe fn chain_inputs(owner: Owner) -> Option<ChainInputs> {
    let take = |cert: &Cert, store: *mut X509_STORE, libctx, propq| {
        let slot = cert.current()?;
        // SAFETY: the slot's live certificate, or NULL (refused below).
        if slot.x509.is_null() || unsafe { X509_up_ref(slot.x509) } == 0 {
            return None;
        }
        let mut chain = Vec::new();
        // SAFETY: the slot's chain, or NULL (-1).
        let n = unsafe { OPENSSL_sk_num(slot.chain.cast()) };
        for i in 0..n {
            // SAFETY: an index in range.
            let x: *mut X509 = unsafe { OPENSSL_sk_value(slot.chain.cast(), i) }.cast();
            // SAFETY: a live certificate of the chain.
            if !x.is_null() && unsafe { X509_up_ref(x) } != 0 {
                chain.push(x);
            }
        }
        let store = if cert.chain_store.is_null() {
            store
        } else {
            cert.chain_store
        };
        // SAFETY: a live store, or NULL.
        if !store.is_null() && unsafe { X509_STORE_up_ref(store) } == 0 {
            return None;
        }
        Some(ChainInputs {
            leaf: slot.x509,
            chain,
            store,
            cert_flags: cert.cert_flags,
            libctx,
            propq,
        })
    };
    match owner {
        Owner::Ctx(c) => {
            // SAFETY: the caller's guarantee.
            let x = unsafe { ctx(c) }?;
            let st = x.state();
            take(&st.cert, st.cert_store, x.libctx, x.propq.clone())
        }
        Owner::Ssl(s) => {
            // SAFETY: as above.
            let x = unsafe { ssl(s) }?;
            let st = x.state();
            // SAFETY: the connection's reference keeps its context alive.
            let c = unsafe { ctx(st.ctx) }?;
            let store = c.state().cert_store;
            take(&st.cert, store, c.libctx, c.propq.clone())
        }
    }
}

/// Whether the owner's current slot has a certificate.
///
/// # Safety
/// The owner is live.
unsafe fn has_cert(owner: Owner) -> bool {
    let has = |cert: &Cert| cert.current().is_some_and(|p| !p.x509.is_null());
    match owner {
        // SAFETY: the caller's guarantee.
        Owner::Ctx(c) => unsafe { ctx(c) }.is_some_and(|x| has(&x.state().cert)),
        // SAFETY: as above.
        Owner::Ssl(s) => unsafe { ssl(s) }.is_some_and(|x| has(&x.state().cert)),
    }
}

/// A new stack holding references to `certs`, or NULL.
///
/// # Safety
/// Each certificate is live.
unsafe fn stack_of(certs: &[*mut X509]) -> *mut stack_st_X509 {
    // SAFETY: no preconditions.
    let sk = unsafe { OPENSSL_sk_new_null() };
    if sk.is_null() {
        return ptr::null_mut();
    }
    for x in certs {
        // SAFETY: the caller's live certificate.
        let ok = unsafe { X509_up_ref(*x) } != 0
            // SAFETY: the stack made above; the reference taken, which it now owns.
            && unsafe { OPENSSL_sk_push(sk, x.cast()) } != 0;
        if !ok {
            // SAFETY: the stack made here, with what it owns.
            unsafe { OPENSSL_sk_pop_free(sk, Some(x509_free)) };
            return ptr::null_mut();
        }
    }
    sk.cast()
}

/// `ssl_build_cert_chain`: the current certificate's chain rebuilt from the store (with
/// `SSL_BUILD_CHAIN_FLAG_CHECK`, from the configured chain alone), without the leaf (and, with
/// `NO_ROOT`, without a self-signed root), each CA certificate passing the security level;
/// 1, 2 when verification failed and `IGNORE_ERROR` allowed it, or 0.
///
/// # Safety
/// The owner is live.
pub(crate) unsafe fn build_cert_chain(owner: Owner, flags: c_long) -> c_long {
    const F: &str = "ssl_build_cert_chain";
    // SAFETY: the caller's guarantee.
    if !unsafe { has_cert(owner) } {
        err::raise(ERR_LIB_SSL, SSL_R_NO_CERTIFICATE_SET, F);
        return 0;
    }
    // SAFETY: as above.
    let Some(inputs) = (unsafe { chain_inputs(owner) }) else {
        err::raise(ERR_LIB_SSL, ERR_R_X509_LIB, F);
        return 0;
    };
    let check = flags & c_long::from(SSL_BUILD_CHAIN_FLAG_CHECK) != 0;
    let mut own_store = ptr::null_mut();
    let mut untrusted = ptr::null_mut();
    let store = if check {
        // SAFETY: no preconditions.
        own_store = unsafe { crate::x509::store::X509_STORE_new() };
        if own_store.is_null() {
            return 0;
        }
        // The configured chain, then the leaf (it might be self-signed).
        let all = inputs
            .chain
            .iter()
            .copied()
            .chain(core::iter::once(inputs.leaf));
        for x in all {
            // SAFETY: the store made here; a live certificate.
            if unsafe { X509_STORE_add_cert(own_store, x) } == 0 {
                // SAFETY: made here.
                unsafe { X509_STORE_free(own_store) };
                return 0;
            }
        }
        own_store
    } else {
        if flags & c_long::from(SSL_BUILD_CHAIN_FLAG_UNTRUSTED) != 0 {
            // SAFETY: the inputs' live certificates.
            untrusted = unsafe { stack_of(&inputs.chain) };
        }
        inputs.store
    };
    let propq = inputs.propq.as_ref().map_or(ptr::null(), |q| q.as_ptr());
    // SAFETY: the context's library context and property query.
    let xs = unsafe { X509_STORE_CTX_new_ex(inputs.libctx, propq) };
    let rv = 'b: {
        if xs.is_null() {
            err::raise(ERR_LIB_SSL, ERR_R_X509_LIB, F);
            break 'b 0;
        }
        // SAFETY: the context made here; the store; the leaf; the untrusted chain, or NULL.
        if unsafe { X509_STORE_CTX_init(xs, store, inputs.leaf, untrusted) } == 0 {
            err::raise(ERR_LIB_SSL, ERR_R_X509_LIB, F);
            break 'b 0;
        }
        let suiteb = inputs.cert_flags & SSL_CERT_FLAG_SUITEB_128_LOS.cast_unsigned();
        // SAFETY: as above.
        unsafe { X509_STORE_CTX_set_flags(xs, core::ffi::c_ulong::from(suiteb)) };
        // Verification runs the store's callbacks: no lock is held.
        // SAFETY: as above.
        let mut i = unsafe { X509_verify_cert(xs) };
        let mut rv = 0;
        if i <= 0 && flags & c_long::from(SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR) != 0 {
            if flags & c_long::from(SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR) != 0 {
                // SAFETY: no preconditions.
                unsafe { ERR_clear_error() };
            }
            i = 1;
            rv = 2;
        }
        if i <= 0 {
            // SAFETY: as above.
            let e = unsafe { X509_STORE_CTX_get_error(xs) };
            // SAFETY: a static string.
            let s = unsafe { X509_verify_cert_error_string(c_long::from(e)) };
            let text = if s.is_null() {
                String::new()
            } else {
                // SAFETY: a NUL-terminated static string.
                unsafe { core::ffi::CStr::from_ptr(s) }
                    .to_string_lossy()
                    .into_owned()
            };
            err::raise_with_text(
                ERR_LIB_SSL,
                SSL_R_CERTIFICATE_VERIFY_FAILED,
                F,
                &format!("Verify error:{text}"),
            );
            break 'b 0;
        }
        // SAFETY: as above, verified.
        let chain = unsafe { X509_STORE_CTX_get1_chain(xs) };
        if chain.is_null() {
            break 'b 0;
        }
        // The leaf comes off the chain.
        // SAFETY: the chain made above.
        let leaf: *mut X509 = unsafe { OPENSSL_sk_shift(chain.cast()) }.cast();
        // SAFETY: the reference the chain held.
        unsafe { X509_free(leaf) };
        if flags & c_long::from(SSL_BUILD_CHAIN_FLAG_NO_ROOT) != 0 {
            // SAFETY: as above.
            let n = unsafe { OPENSSL_sk_num(chain.cast()) };
            if n > 0 {
                // SAFETY: the last index.
                let last: *mut X509 =
                    unsafe { OPENSSL_sk_value(chain.cast(), n.saturating_sub(1)) }.cast();
                // SAFETY: a live certificate of the chain.
                if unsafe { X509_get_extension_flags(last) } & EXFLAG_SS.cast_unsigned() != 0 {
                    // SAFETY: as above.
                    let root: *mut X509 = unsafe { OPENSSL_sk_pop(chain.cast()) }.cast();
                    // SAFETY: the reference the chain held.
                    unsafe { X509_free(root) };
                }
            }
        }
        // Each CA certificate passes the security level (the leaf was checked when set).
        // SAFETY: as above.
        let n = unsafe { OPENSSL_sk_num(chain.cast()) };
        for k in 0..n {
            // SAFETY: an index in range.
            let x: *mut X509 = unsafe { OPENSSL_sk_value(chain.cast(), k) }.cast();
            // SAFETY: the live owner; a certificate of the chain (the security callback runs
            // with no lock held).
            let r = unsafe { security_cert(owner, x, false) };
            if r != 1 {
                err::raise(ERR_LIB_SSL, r, F);
                // SAFETY: the chain made above, with its references.
                unsafe { OPENSSL_sk_pop_free(chain.cast(), Some(x509_free)) };
                break 'b 0;
            }
        }
        // SAFETY: the live owner; the chain, which it takes.
        unsafe { install_chain(owner, chain) };
        if rv == 0 { 1 } else { rv }
    };
    // SAFETY: made here, or NULL.
    unsafe { X509_STORE_CTX_free(xs) };
    if !own_store.is_null() {
        // SAFETY: made here.
        unsafe { X509_STORE_free(own_store) };
    }
    if !untrusted.is_null() {
        // SAFETY: made here, with its references.
        unsafe { OPENSSL_sk_pop_free(untrusted.cast(), Some(x509_free)) };
    }
    drop(inputs);
    rv
}

/// Makes `chain` the current slot's chain; the old one is freed with no lock held.
///
/// # Safety
/// The owner is live; `chain` a live stack it takes.
unsafe fn install_chain(owner: Owner, chain: *mut stack_st_X509) {
    let swap = |cert: &mut Cert| {
        cert.current_mut()
            .map(|p| core::mem::replace(&mut p.chain, chain))
    };
    let old = match owner {
        // SAFETY: the caller's guarantee.
        Owner::Ctx(c) => unsafe { ctx(c) }.and_then(|x| swap(&mut x.state().cert)),
        // SAFETY: as above.
        Owner::Ssl(s) => unsafe { ssl(s) }.and_then(|x| swap(&mut x.state().cert)),
    };
    let old = old.unwrap_or(chain);
    // SAFETY: the old chain (or the new one, when no slot took it), with its references.
    unsafe { OPENSSL_sk_pop_free(old.cast(), Some(x509_free)) };
}

/// The connection ctrl commands about certificates and temporary keys: `Some` result for those
/// handled.
///
/// # Safety
/// `s` is a live connection; `parg` is what `cmd` documents.
pub(crate) unsafe fn ssl_ctrl(
    s: *mut SSL,
    x: &Ssl,
    cmd: core::ffi::c_int,
    larg: c_long,
    parg: *mut c_void,
) -> Option<c_long> {
    Some(match cmd {
        SSL_CTRL_GET_CLIENT_CERT_TYPES => {
            let st = x.state();
            if st.server {
                return Some(0);
            }
            let Some(types) = st.drv.tls.as_deref().and_then(|c| c.certificate_types()) else {
                return Some(0);
            };
            if !parg.is_null() {
                // SAFETY: the caller's slot for a pointer; the types stay with the connection.
                unsafe { parg.cast::<*const u8>().write(types.as_ptr()) };
            }
            c_long::try_from(types.len()).unwrap_or(0)
        }
        SSL_CTRL_SET_CLIENT_CERT_TYPES => {
            let mut st = x.state();
            if !st.server {
                return Some(0);
            }
            // SAFETY: the caller's `larg` octets at `parg`, or NULL.
            unsafe { set_req_cert_type(&mut st.cert, parg.cast(), larg) }
        }
        SSL_CTRL_GET_IANA_GROUPS => {
            let st = x.state();
            let groups = st
                .drv
                .tls
                .as_deref()
                .map(|c| c.negotiated().peer_groups.as_slice());
            let groups = groups.unwrap_or_default();
            if !parg.is_null() {
                let p = if groups.is_empty() {
                    ptr::null()
                } else {
                    groups.as_ptr()
                };
                // SAFETY: the caller's slot for a pointer; the list stays with the connection.
                unsafe { parg.cast::<*const u16>().write(p) };
            }
            c_long::try_from(groups.len()).unwrap_or(0)
        }
        SSL_CTRL_GET_TMP_KEY => {
            let st = x.state();
            let share = st
                .drv
                .tls
                .as_deref()
                .and_then(|c| c.handshake().sh.own_tmp.clone());
            let prov = st.drv.provider.clone();
            drop(st);
            let key = match (share, prov) {
                (Some((id, octets)), Some(p)) => p.peer_share_key(id, &octets),
                _ => None,
            };
            match key {
                Some(k) if !parg.is_null() => {
                    // SAFETY: the caller's slot; a new key, the caller's reference.
                    unsafe { parg.cast::<*mut EVP_PKEY>().write(k) };
                    1
                }
                Some(k) => {
                    // SAFETY: not handed out.
                    unsafe { crate::evp::pkey::EVP_PKEY_free(k) };
                    0
                }
                None => 0,
            }
        }
        // SAFETY: the live connection; the caller's DH key.
        SSL_CTRL_SET_TMP_DH => unsafe { set_tmp_dh(Owner::Ssl(s), parg.cast()) },
        // SAFETY: as above.
        SSL_CTRL_BUILD_CERT_CHAIN => unsafe { build_cert_chain(Owner::Ssl(s), larg) },
        _ => return None,
    })
}

/// The context ctrl commands about certificates and DH parameters: `Some` result for those
/// handled.
///
/// # Safety
/// `c` is a live context; `parg` is what `cmd` documents.
pub(crate) unsafe fn ctx_ctrl(
    c: *mut SSL_CTX,
    cmd: core::ffi::c_int,
    larg: c_long,
    parg: *mut c_void,
) -> Option<c_long> {
    Some(match cmd {
        SSL_CTRL_SET_CLIENT_CERT_TYPES => {
            // SAFETY: the caller's guarantee.
            let x = unsafe { ctx(c) }?;
            let mut st = x.state();
            // SAFETY: the caller's `larg` octets at `parg`, or NULL.
            unsafe { set_req_cert_type(&mut st.cert, parg.cast(), larg) }
        }
        // SAFETY: the live context; the caller's DH key.
        SSL_CTRL_SET_TMP_DH => unsafe { set_tmp_dh(Owner::Ctx(c), parg.cast()) },
        // SAFETY: as above.
        SSL_CTRL_BUILD_CERT_CHAIN => unsafe { build_cert_chain(Owner::Ctx(c), larg) },
        _ => return None,
    })
}
