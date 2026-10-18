//! A context's or connection's certificates (`CERT`, `ssl_cert.c`, `ssl_rsa.c`): one slot per
//! key type, each with a certificate, its private key, and a chain; the current slot; the
//! security level and its callback; and the temporary DH key. A connection starts with a copy
//! of its context's (`ssl_cert_dup`), sharing the objects by reference.

use core::ffi::{c_int, c_long, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    DTLS1_2_VERSION, ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER, ERR_R_X509_LIB, EVP_PKEY, NID_ED448,
    NID_ED25519, NID_X9_62_id_ecPublicKey, NID_dsa, NID_id_GostR3410_2001,
    NID_id_GostR3410_2012_256, NID_id_GostR3410_2012_512, NID_rsaEncryption, NID_rsassaPss, SSL,
    SSL_CERT_SET_FIRST, SSL_CERT_SET_NEXT, SSL_CTX, SSL_R_CA_KEY_TOO_SMALL,
    SSL_R_ECC_CERT_NOT_FOR_SIGNING, SSL_R_EE_KEY_TOO_SMALL, SSL_R_UNKNOWN_CERTIFICATE_TYPE,
    SSL_R_X509_LIB, SSL_SECOP_CA_KEY, SSL_SECOP_CIPHER_CHECK, SSL_SECOP_CIPHER_SHARED,
    SSL_SECOP_CIPHER_SUPPORTED, SSL_SECOP_COMPRESSION, SSL_SECOP_EE_KEY, SSL_SECOP_TICKET,
    SSL_SECOP_TMP_DH, SSL_SECOP_VERSION, TLS1_1_VERSION, X509, X509_STORE, stack_st_X509,
};

use super::types::{CertCb, SSL_PKEY_ECC, SSL_PKEY_NUM, SSL_PKEY_RSA, SecCb, TmpDhCb};
use crate::err;
use crate::evp::pkey::{
    EVP_PKEY_can_sign, EVP_PKEY_copy_parameters, EVP_PKEY_free, EVP_PKEY_get_security_bits,
    EVP_PKEY_is_a, EVP_PKEY_up_ref,
};
use crate::ffi::ffi_callback;
use crate::objects::{OBJ_nid2ln, OBJ_nid2sn};
use crate::stack::{OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value};
use crate::x509::cert::{
    OSSL_STACK_OF_X509_free, X509_chain_up_ref, X509_check_private_key, X509_free,
    X509_get0_pubkey, X509_up_ref,
};
use crate::x509::purpose::X509_cmp;
use crate::x509::store::{X509_STORE_free, X509_STORE_up_ref};

/// One slot (`CERT_PKEY`).
#[derive(Debug)]
pub(crate) struct CertPkey {
    /// The certificate (a reference held), or NULL.
    pub(crate) x509: *mut X509,
    /// Its private key (a reference held), or NULL.
    pub(crate) privatekey: *mut EVP_PKEY,
    /// The chain sent after it (owned), or NULL.
    pub(crate) chain: *mut stack_st_X509,
}

impl Default for CertPkey {
    fn default() -> Self {
        Self {
            x509: ptr::null_mut(),
            privatekey: ptr::null_mut(),
            chain: ptr::null_mut(),
        }
    }
}

/// One reference taken out of a certificate configuration.
#[derive(Debug)]
enum Release {
    X509(*mut X509),
    Pkey(*mut EVP_PKEY),
    Chain(*mut stack_st_X509),
    Store(*mut X509_STORE),
}

/// References taken out of a certificate configuration under its owner's lock, freed when
/// this is dropped, after the lock: freeing can run applications' ex_data callbacks, which
/// may call back into the same object (security rule 7). Declare it before the lock is taken.
#[derive(Debug, Default)]
pub(crate) struct Released(Vec<Release>);

impl Released {
    /// A certificate reference, or NULL.
    pub(crate) fn x509(&mut self, p: *mut X509) {
        if !p.is_null() {
            self.0.push(Release::X509(p));
        }
    }

    /// A key reference, or NULL.
    pub(crate) fn pkey(&mut self, p: *mut EVP_PKEY) {
        if !p.is_null() {
            self.0.push(Release::Pkey(p));
        }
    }

    /// An owned chain, or NULL.
    pub(crate) fn chain(&mut self, p: *mut stack_st_X509) {
        if !p.is_null() {
            self.0.push(Release::Chain(p));
        }
    }

    /// A store reference, or NULL.
    pub(crate) fn store(&mut self, p: *mut X509_STORE) {
        if !p.is_null() {
            self.0.push(Release::Store(p));
        }
    }

    /// What a slot holds.
    pub(crate) fn slot(&mut self, p: CertPkey) {
        self.x509(p.x509);
        self.pkey(p.privatekey);
        self.chain(p.chain);
    }
}

impl Drop for Released {
    fn drop(&mut self) {
        for r in self.0.drain(..) {
            match r {
                // SAFETY: a reference the configuration held, now ours.
                Release::X509(p) => unsafe { X509_free(p) },
                // SAFETY: as above.
                Release::Pkey(p) => unsafe { EVP_PKEY_free(p) },
                // SAFETY: as above.
                Release::Chain(p) => unsafe { OSSL_STACK_OF_X509_free(p) },
                // SAFETY: as above.
                Release::Store(p) => unsafe { X509_STORE_free(p) },
            }
        }
    }
}

/// The certificate configuration (`CERT`).
#[derive(Debug)]
pub(crate) struct Cert {
    /// The slots, indexed by `SSL_PKEY_*`.
    pub(crate) pkeys: [CertPkey; SSL_PKEY_NUM],
    /// The current slot (`key`).
    pub(crate) key: usize,
    /// `cert_flags` (`SSL_CERT_FLAG_*`).
    pub(crate) cert_flags: u32,
    /// The security callback (`sec_cb`): [`default_security_callback`] unless replaced.
    pub(crate) sec_cb: SecCb,
    /// The security level (`sec_level`).
    pub(crate) sec_level: c_int,
    /// The callback's data (`sec_ex`).
    pub(crate) sec_ex: *mut c_void,
    /// The temporary DH key (owned), or NULL.
    pub(crate) dh_tmp: *mut EVP_PKEY,
    /// Whether the DH parameters are chosen automatically (`SSL_set_dh_auto`).
    pub(crate) dh_tmp_auto: c_int,
    /// The deprecated temporary DH callback.
    pub(crate) dh_tmp_cb: TmpDhCb,
    /// The certificate callback and its argument.
    pub(crate) cert_cb: CertCb,
    /// See `cert_cb`.
    pub(crate) cert_cb_arg: *mut c_void,
    /// The store verifying the peer (a reference held), or NULL for the context's.
    pub(crate) verify_store: *mut X509_STORE,
    /// The store building our chain (a reference held), or NULL for the context's.
    pub(crate) chain_store: *mut X509_STORE,
    /// The PSK identity hint, or `None`.
    pub(crate) psk_identity_hint: Option<CString>,
}

impl Cert {
    /// `ssl_cert_new`: empty slots, the RSA slot current, the default security callback and
    /// level.
    pub(crate) fn new() -> Self {
        Self {
            pkeys: Default::default(),
            key: SSL_PKEY_RSA,
            cert_flags: 0,
            sec_cb: Some(default_security_callback),
            sec_level: rustyssl_abi::OPENSSL_TLS_SECURITY_LEVEL,
            sec_ex: ptr::null_mut(),
            dh_tmp: ptr::null_mut(),
            dh_tmp_auto: 0,
            dh_tmp_cb: None,
            cert_cb: None,
            cert_cb_arg: ptr::null_mut(),
            verify_store: ptr::null_mut(),
            chain_store: ptr::null_mut(),
            psk_identity_hint: None,
        }
    }

    /// `ssl_cert_dup`: the same settings, sharing every certificate, key, chain member, and
    /// store by reference; `None` if a chain couldn't be copied.
    pub(crate) fn dup(&self) -> Option<Self> {
        let mut ret = Self::new();
        ret.key = self.key;
        for (to, from) in ret.pkeys.iter_mut().zip(self.pkeys.iter()) {
            if !from.x509.is_null() {
                // SAFETY: the original's live certificate.
                unsafe { X509_up_ref(from.x509) };
                to.x509 = from.x509;
            }
            if !from.privatekey.is_null() {
                // SAFETY: as above, its key.
                unsafe { EVP_PKEY_up_ref(from.privatekey) };
                to.privatekey = from.privatekey;
            }
            if !from.chain.is_null() {
                // SAFETY: as above, its chain.
                to.chain = unsafe { X509_chain_up_ref(from.chain) };
                if to.chain.is_null() {
                    err::raise(ERR_LIB_SSL, ERR_R_X509_LIB, "ssl_cert_dup");
                    return None;
                }
            }
        }
        if !self.dh_tmp.is_null() {
            // SAFETY: the original's live key.
            unsafe { EVP_PKEY_up_ref(self.dh_tmp) };
            ret.dh_tmp = self.dh_tmp;
        }
        ret.dh_tmp_cb = self.dh_tmp_cb;
        ret.dh_tmp_auto = self.dh_tmp_auto;
        ret.cert_flags = self.cert_flags;
        ret.cert_cb = self.cert_cb;
        ret.cert_cb_arg = self.cert_cb_arg;
        if !self.verify_store.is_null() {
            // SAFETY: the original's live store.
            unsafe { X509_STORE_up_ref(self.verify_store) };
            ret.verify_store = self.verify_store;
        }
        if !self.chain_store.is_null() {
            // SAFETY: as above.
            unsafe { X509_STORE_up_ref(self.chain_store) };
            ret.chain_store = self.chain_store;
        }
        ret.sec_cb = self.sec_cb;
        ret.sec_level = self.sec_level;
        ret.sec_ex = self.sec_ex;
        ret.psk_identity_hint.clone_from(&self.psk_identity_hint);
        Some(ret)
    }

    /// `ssl_cert_clear_certs`: empties every slot (the current one stays where it is), its
    /// references going to `rel`.
    pub(crate) fn clear_certs(&mut self, rel: &mut Released) {
        for p in &mut self.pkeys {
            rel.slot(core::mem::take(p));
        }
    }

    /// The current slot.
    pub(crate) fn current(&self) -> Option<&CertPkey> {
        self.pkeys.get(self.key)
    }

    /// The current slot, to change.
    pub(crate) fn current_mut(&mut self) -> Option<&mut CertPkey> {
        self.pkeys.get_mut(self.key)
    }

    /// `ssl_cert_select_current`: the slot with `x` (the same object first, then an equal
    /// certificate) and a key becomes current; 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub(crate) unsafe fn select_current(&mut self, x: *mut X509) -> c_int {
        if x.is_null() {
            return 0;
        }
        if let Some(i) = self
            .pkeys
            .iter()
            .position(|p| p.x509 == x && !p.privatekey.is_null())
        {
            self.key = i;
            return 1;
        }
        let found = self.pkeys.iter().position(|p| {
            // SAFETY: the slot's live certificate; the caller's.
            !p.privatekey.is_null() && !p.x509.is_null() && unsafe { X509_cmp(p.x509, x) } == 0
        });
        match found {
            Some(i) => {
                self.key = i;
                1
            }
            None => 0,
        }
    }

    /// `ssl_cert_set_current`: the first (or next) complete slot becomes current; 1, or 0.
    pub(crate) fn set_current(&mut self, op: c_long) -> c_int {
        let start = if op == c_long::from(SSL_CERT_SET_FIRST) {
            0
        } else if op == c_long::from(SSL_CERT_SET_NEXT) {
            match self.key.checked_add(1) {
                Some(i) if i < SSL_PKEY_NUM => i,
                _ => return 0,
            }
        } else {
            return 0;
        };
        let found = self
            .pkeys
            .iter()
            .enumerate()
            .skip(start)
            .find(|(_, p)| !p.x509.is_null() && !p.privatekey.is_null());
        match found {
            Some((i, _)) => {
                self.key = i;
                1
            }
            None => 0,
        }
    }

    /// `ssl_cert_set_cert_store`: replaces the verify (or chain) store, taking a reference
    /// first when `take_ref`, the old one going to `rel`; 1, or 0.
    ///
    /// # Safety
    /// `store` is NULL or a live store.
    pub(crate) unsafe fn set_store(
        &mut self,
        store: *mut X509_STORE,
        chain: bool,
        take_ref: bool,
        rel: &mut Released,
    ) -> c_int {
        // SAFETY: the caller's store.
        if take_ref && !store.is_null() && unsafe { X509_STORE_up_ref(store) } == 0 {
            return 0;
        }
        let slot = if chain {
            &mut self.chain_store
        } else {
            &mut self.verify_store
        };
        rel.store(core::mem::replace(slot, store));
        1
    }
}

impl Drop for Cert {
    fn drop(&mut self) {
        // SAFETY: our own references, each NULL or live.
        unsafe { EVP_PKEY_free(self.dh_tmp) };
        let mut rel = Released::default();
        self.clear_certs(&mut rel);
        rel.store(self.verify_store);
        rel.store(self.chain_store);
    }
}

/// The key types of the built-in slots, in `SSL_PKEY_*` order (`ssl_cert_table.h`).
const PKEY_NIDS: [c_int; SSL_PKEY_NUM] = [
    NID_rsaEncryption,
    NID_rsassaPss,
    NID_dsa,
    NID_X9_62_id_ecPublicKey,
    NID_id_GostR3410_2001,
    NID_id_GostR3410_2012_256,
    NID_id_GostR3410_2012_512,
    NID_ED25519,
    NID_ED448,
];

/// Whether `pk` is of the type `nid` names (by its short or long name).
///
/// # Safety
/// `pk` is a live key.
unsafe fn is_type(pk: *const EVP_PKEY, nid: c_int) -> bool {
    // SAFETY: no preconditions.
    let sn = unsafe { OBJ_nid2sn(nid) };
    // SAFETY: the caller's key; a static name, or NULL.
    if !sn.is_null() && unsafe { EVP_PKEY_is_a(pk, sn) } != 0 {
        return true;
    }
    // SAFETY: no preconditions.
    let ln = unsafe { OBJ_nid2ln(nid) };
    // SAFETY: as above.
    !ln.is_null() && unsafe { EVP_PKEY_is_a(pk, ln) } != 0
}

/// `ssl_cert_lookup_by_pkey`: the slot for `pk`'s type. Keys whose signature algorithms come
/// from the providers' `TLS-SIGALG` capability (ML-DSA in the default provider) have slots of
/// their own in OpenSSL, which rustyssl doesn't build yet: those abort rather than be refused
/// (security rule 10).
///
/// # Safety
/// `pk` is a live key.
pub(crate) unsafe fn lookup_by_pkey(pk: *const EVP_PKEY) -> Option<usize> {
    if let Some(i) = PKEY_NIDS.iter().position(|&nid| {
        // SAFETY: the caller's key.
        unsafe { is_type(pk, nid) }
    }) {
        return Some(i);
    }
    for name in [c"ML-DSA-44", c"ML-DSA-65", c"ML-DSA-87"] {
        // SAFETY: the caller's key; a static name.
        if unsafe { EVP_PKEY_is_a(pk, name.as_ptr()) } != 0 {
            crate::stub::unimplemented(
                "certificates with providers' TLS-SIGALG key types (ML-DSA)",
            );
        }
    }
    None
}

/// `ssl_set_cert`: `x` goes into its key type's slot, which becomes current; a key already
/// there that doesn't match it is dropped. 1, or 0 (with the error raised). Replaced
/// references go to `rel`.
///
/// # Safety
/// `x` is a live certificate.
pub(crate) unsafe fn set_cert(c: &mut Cert, x: *mut X509, rel: &mut Released) -> c_int {
    const F: &str = "ssl_set_cert";
    // SAFETY: the caller's certificate.
    let pkey = unsafe { X509_get0_pubkey(x) };
    if pkey.is_null() {
        err::raise(ERR_LIB_SSL, SSL_R_X509_LIB, F);
        return 0;
    }
    // SAFETY: the certificate's key.
    let Some(i) = (unsafe { lookup_by_pkey(pkey) }) else {
        err::raise(ERR_LIB_SSL, SSL_R_UNKNOWN_CERTIFICATE_TYPE, F);
        return 0;
    };
    // SAFETY: as above.
    if i == SSL_PKEY_ECC && unsafe { EVP_PKEY_can_sign(pkey) } == 0 {
        err::raise(ERR_LIB_SSL, SSL_R_ECC_CERT_NOT_FOR_SIGNING, F);
        return 0;
    }
    let Some(slot) = c.pkeys.get_mut(i) else {
        return 0;
    };
    if !slot.privatekey.is_null() {
        // Errors from the copy are deliberately ignored, as some key types can't do it.
        // SAFETY: the certificate's key; the slot's.
        unsafe { EVP_PKEY_copy_parameters(pkey, slot.privatekey) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
        // SAFETY: the certificate; the slot's key.
        if unsafe { X509_check_private_key(x, slot.privatekey) } == 0 {
            // A mismatch isn't a failure: the key is dropped (to switch certificate and key,
            // the certificate goes first).
            rel.pkey(core::mem::replace(&mut slot.privatekey, ptr::null_mut()));
            // SAFETY: no preconditions.
            unsafe { crate::err::ERR_clear_error() };
        }
    }
    // SAFETY: the caller's certificate.
    if unsafe { X509_up_ref(x) } == 0 {
        return 0;
    }
    rel.x509(core::mem::replace(&mut slot.x509, x));
    c.key = i;
    1
}

/// `ssl_set_pkey`: `pkey` goes into its type's slot (checked against a certificate already
/// there), which becomes current. 1, or 0. The replaced key goes to `rel`.
///
/// # Safety
/// `pkey` is a live key.
pub(crate) unsafe fn set_pkey(c: &mut Cert, pkey: *mut EVP_PKEY, rel: &mut Released) -> c_int {
    // SAFETY: the caller's key.
    let Some(i) = (unsafe { lookup_by_pkey(pkey) }) else {
        err::raise(ERR_LIB_SSL, SSL_R_UNKNOWN_CERTIFICATE_TYPE, "ssl_set_pkey");
        return 0;
    };
    let Some(slot) = c.pkeys.get_mut(i) else {
        return 0;
    };
    // SAFETY: the slot's certificate; the caller's key.
    if !slot.x509.is_null() && unsafe { X509_check_private_key(slot.x509, pkey) } == 0 {
        return 0;
    }
    // SAFETY: the caller's key.
    if unsafe { EVP_PKEY_up_ref(pkey) } == 0 {
        return 0;
    }
    rel.pkey(core::mem::replace(&mut slot.privatekey, pkey));
    c.key = i;
    1
}

/// Pushes `x` (taken) onto the current slot's chain, made if need be: 1, or 0.
///
/// # Safety
/// `x` is a live certificate whose reference the chain takes on success.
pub(crate) unsafe fn add0_chain_cert(c: &mut Cert, x: *mut X509) -> c_int {
    let Some(cpk) = c.current_mut() else { return 0 };
    if cpk.chain.is_null() {
        // SAFETY: no preconditions.
        cpk.chain = unsafe { OPENSSL_sk_new_null() }.cast();
    }
    // SAFETY: the chain, or NULL (which fails); the certificate.
    c_int::from(!cpk.chain.is_null() && unsafe { OPENSSL_sk_push(cpk.chain.cast(), x.cast()) } != 0)
}

/// Whom a security check is for: a context or a connection.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Owner {
    /// A context.
    Ctx(*const SSL_CTX),
    /// A connection.
    Ssl(*const SSL),
}

impl Owner {
    /// The certificate configuration's security callback, level, and data.
    ///
    /// # Safety
    /// The owner is a live object.
    unsafe fn security_settings(self) -> Option<(SecCb, *mut c_void)> {
        match self {
            // SAFETY: the caller's guarantee.
            Self::Ctx(c) => unsafe { super::ctx::ctx(c) }.map(|c| {
                let st = c.state();
                (st.cert.sec_cb, st.cert.sec_ex)
            }),
            // SAFETY: as above.
            Self::Ssl(s) => unsafe { super::conn::ssl(s) }.map(|s| {
                let st = s.state();
                (st.cert.sec_cb, st.cert.sec_ex)
            }),
        }
    }
}

/// `ssl_security`/`ssl_ctx_security`: the owner's security callback asked about `op`, called
/// with no lock held. As in OpenSSL, a NULL callback (`SSL_CTX_set_security_callback(ctx,
/// NULL)`) is called anyway: here that refuses, where OpenSSL crashes.
///
/// # Safety
/// The owner is a live object; `other` is what `op` passes (or NULL).
pub(crate) unsafe fn security(
    owner: Owner,
    op: c_int,
    bits: c_int,
    nid: c_int,
    other: *mut c_void,
) -> bool {
    // SAFETY: the caller's guarantee.
    let Some((Some(cb), ex)) = (unsafe { owner.security_settings() }) else {
        return false;
    };
    let (s, c) = match owner {
        Owner::Ctx(c) => (ptr::null(), c),
        Owner::Ssl(s) => (s, ptr::null()),
    };
    // SAFETY: the application's (or our default) callback with the owner, outside any lock.
    unsafe { cb(s, c, op, bits, nid, other, ex) != 0 }
}

/// `ssl_security_cert`: whether `x`'s key is strong enough for an end-entity (`is_ee`) or CA
/// certificate: 1, or the `SSL_R_*` reason to raise.
///
/// # Safety
/// The owner is live; `x` a live certificate.
pub(crate) unsafe fn security_cert(owner: Owner, x: *mut X509, is_ee: bool) -> c_int {
    // SAFETY: the caller's certificate.
    let pkey = unsafe { X509_get0_pubkey(x) };
    let secbits = if pkey.is_null() {
        -1
    } else {
        // SAFETY: the certificate's key.
        unsafe { EVP_PKEY_get_security_bits(pkey) }
    };
    let (op, reason) = if is_ee {
        (SSL_SECOP_EE_KEY, SSL_R_EE_KEY_TOO_SMALL)
    } else {
        (SSL_SECOP_CA_KEY, SSL_R_CA_KEY_TOO_SMALL)
    };
    // SAFETY: the caller's guarantee; the certificate as the operation's object.
    if unsafe { security(owner, op, secbits, 0, x.cast()) } {
        1
    } else {
        reason
    }
}

/// `ssl_get_security_level_bits`'s table: the minimum security in bits at each level.
const MINBITS: [c_int; 6] = [0, 80, 112, 128, 192, 256];

ffi_callback! {
    /// `ssl_security_default_callback`: OpenSSL's policy for each security level.
    ///
    /// # Safety
    /// `s` and `ctx` are NULL or live (one of them is set).
    pub(crate) unsafe extern "C" fn default_security_callback(s: *const SSL, ctx: *const SSL_CTX, op: c_int, bits: c_int, nid: c_int, _other: *mut c_void, _ex: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let level = if ctx.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { super::conn::ssl(s) }.map_or(0, |x| x.state().cert.sec_level)
        } else {
            // SAFETY: as above.
            unsafe { super::ctx::ctx(ctx) }.map_or(0, |x| x.state().cert.sec_level)
        };
        let level = level.clamp(0, 5);
        let minbits = MINBITS.get(usize::try_from(level).unwrap_or(0)).copied().unwrap_or(0);
        if level == 0 {
            // No DH keys weaker than 1024 bits even at level 0; anything else goes.
            return c_int::from(!(op == SSL_SECOP_TMP_DH && bits < 80));
        }
        match op {
            SSL_SECOP_CIPHER_SUPPORTED | SSL_SECOP_CIPHER_SHARED | SSL_SECOP_CIPHER_CHECK => {
                // The cipher operations look into the SSL_CIPHER, which comes with the cipher
                // suites.
                crate::stub::unimplemented("the default security callback's cipher operations")
            }
            SSL_SECOP_VERSION => {
                // SAFETY: the caller's guarantee.
                let Some(x) = (unsafe { super::conn::ssl(s) }) else { return 0 };
                let dtls = x.state().method.dtls;
                if dtls {
                    // DTLS 1.0 only at level 0 (DTLS versions count down).
                    c_int::from(!super::ctx::dtls_lt(nid, DTLS1_2_VERSION))
                } else {
                    // SSLv3, TLS 1.0 and TLS 1.1 only at level 0.
                    c_int::from(nid > TLS1_1_VERSION)
                }
            }
            SSL_SECOP_COMPRESSION => c_int::from(level < 2),
            SSL_SECOP_TICKET => c_int::from(level < 3),
            _ => c_int::from(bits >= minbits),
        }
    }
}

/// A connection's or context's certificate configuration, read or changed under its lock.
///
/// # Safety
/// The owner is a live object.
pub(crate) unsafe fn with_cert<R>(owner: Owner, f: impl FnOnce(&mut Cert) -> R) -> Option<R> {
    match owner {
        // SAFETY: the caller's guarantee.
        Owner::Ctx(c) => unsafe { super::ctx::ctx(c) }.map(|c| f(&mut c.state().cert)),
        // SAFETY: as above.
        Owner::Ssl(s) => unsafe { super::conn::ssl(s) }.map(|s| f(&mut s.state().cert)),
    }
}

/// Raises the reason a security check returned.
pub(crate) fn raise_reason(reason: c_int, f: &str) {
    err::raise(ERR_LIB_SSL, reason, f);
}

/// `ssl_cert_set0_chain`: every member passes the CA check, then replaces the current slot's
/// chain (taken; NULL empties it). 1, or 0.
///
/// # Safety
/// The owner is live; `chain` NULL or a live list of certificates the slot takes on success.
pub(crate) unsafe fn set0_chain(owner: Owner, chain: *mut stack_st_X509) -> c_int {
    // SAFETY: the caller's list, or NULL (-1).
    let n = unsafe { OPENSSL_sk_num(chain.cast()) };
    for i in 0..n {
        // SAFETY: an index in range.
        let x: *mut X509 = unsafe { OPENSSL_sk_value(chain.cast(), i) }.cast();
        // SAFETY: the owner; a member of the list.
        let r = unsafe { security_cert(owner, x, false) };
        if r != 1 {
            raise_reason(r, "ssl_cert_set0_chain");
            return 0;
        }
    }
    let mut rel = Released::default();
    let f = |c: &mut Cert| match c.current_mut() {
        Some(cpk) => {
            rel.chain(core::mem::replace(&mut cpk.chain, chain));
            1
        }
        None => 0,
    };
    // SAFETY: the caller's guarantee.
    unsafe { with_cert(owner, f) }.unwrap_or(0)
}

/// `ssl_cert_set1_chain`: as [`set0_chain`] with a copy holding new references.
///
/// # Safety
/// As for [`set0_chain`], the list not taken.
pub(crate) unsafe fn set1_chain(owner: Owner, chain: *mut stack_st_X509) -> c_int {
    if chain.is_null() {
        // SAFETY: the caller's guarantee.
        return unsafe { set0_chain(owner, ptr::null_mut()) };
    }
    // SAFETY: the caller's list.
    let dchain = unsafe { X509_chain_up_ref(chain) };
    if dchain.is_null() {
        return 0;
    }
    // SAFETY: the owner; the copy, taken on success.
    if unsafe { set0_chain(owner, dchain) } == 0 {
        // SAFETY: the copy, not taken.
        unsafe { OSSL_STACK_OF_X509_free(dchain) };
        return 0;
    }
    1
}

/// `ssl_cert_add0_chain_cert` with the CA check first: 1, or 0.
///
/// # Safety
/// The owner is live; `x` a live certificate the chain takes on success.
pub(crate) unsafe fn add0_chain(owner: Owner, x: *mut X509) -> c_int {
    // SAFETY: the caller's guarantee.
    let r = unsafe { security_cert(owner, x, false) };
    if r != 1 {
        raise_reason(r, "ssl_cert_add0_chain_cert");
        return 0;
    }
    let f = |c: &mut Cert| {
        // SAFETY: the caller's certificate.
        unsafe { add0_chain_cert(c, x) }
    };
    // SAFETY: as above.
    unsafe { with_cert(owner, f) }.unwrap_or(0)
}

/// `ssl_cert_add1_chain_cert`: as [`add0_chain`] with a new reference.
///
/// # Safety
/// As for [`add0_chain`], `x` not taken.
pub(crate) unsafe fn add1_chain(owner: Owner, x: *mut X509) -> c_int {
    // SAFETY: the caller's certificate.
    if unsafe { X509_up_ref(x) } == 0 {
        return 0;
    }
    // SAFETY: the caller's guarantee; the new reference.
    if unsafe { add0_chain(owner, x) } == 0 {
        // SAFETY: the reference taken above.
        unsafe { X509_free(x) };
        return 0;
    }
    1
}

/// Checks a NULL argument as OpenSSL does (`ERR_R_PASSED_NULL_PARAMETER`).
pub(crate) fn null_argument(f: &str) {
    err::raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER, f);
}
