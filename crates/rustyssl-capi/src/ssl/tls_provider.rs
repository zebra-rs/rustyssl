//! The TLS core's cryptography over EVP (ADR 0002): every algorithm is fetched from a library
//! context with a property query, as libssl fetches from its `SSL_CTX`'s, so the providers
//! loaded there (third-party ones included) supply the hashes, MACs, record ciphers, groups,
//! and signatures.
//!
//! Keys stay `EVP_PKEY` objects: the connection's [`EvpProvider`] keeps a small registry from
//! [`KeyId`]s to the keys (each holding a reference), and certificates arrive as DER.

#![allow(
    dead_code,
    reason = "the TLS driver creates an EvpProvider for each SSL; until it lands, the tests do"
)]

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::{Mutex, PoisonError};

use rustyssl_abi::{
    EVP_CIPHER, EVP_CIPHER_CTX, EVP_CTRL_AEAD_GET_TAG, EVP_CTRL_AEAD_SET_IVLEN,
    EVP_CTRL_AEAD_SET_TAG, EVP_MAC_CTX, EVP_MD, EVP_MD_CTX, EVP_PKEY, EVP_PKEY_CTX,
    EVP_PKEY_KEY_PARAMETERS, EVP_PKEY_PUBLIC_KEY, OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION,
    OSSL_CAPABILITY_TLS_GROUP_ALG, OSSL_CAPABILITY_TLS_GROUP_ID, OSSL_CAPABILITY_TLS_GROUP_IS_KEM,
    OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, OSSL_CAPABILITY_TLS_GROUP_MAX_TLS,
    OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,
    OSSL_CAPABILITY_TLS_GROUP_NAME, OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,
    OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT,
    OSSL_CAPABILITY_TLS_SIGALG_HASH_NAME, OSSL_CAPABILITY_TLS_SIGALG_HASH_OID,
    OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME, OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE,
    OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE_OID, OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS,
    OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS, OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS,
    OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS, OSSL_CAPABILITY_TLS_SIGALG_NAME,
    OSSL_CAPABILITY_TLS_SIGALG_OID, OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS,
    OSSL_CAPABILITY_TLS_SIGALG_SIG_NAME, OSSL_CAPABILITY_TLS_SIGALG_SIG_OID, OSSL_LIB_CTX,
    OSSL_MAC_PARAM_DIGEST, OSSL_MAC_PARAM_TLS_DATA_SIZE, OSSL_PARAM, OSSL_PARAM_UTF8_STRING,
    OSSL_PKEY_PARAM_FFC_G, OSSL_PKEY_PARAM_FFC_P, OSSL_PKEY_PARAM_PUB_KEY, OSSL_PROVIDER,
    RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING, RSA_PKCS1_WITH_TLS_PADDING, RSA_PSS_SALTLEN_DIGEST,
};
use rustyssl_tls::consts::sigscheme;
use rustyssl_tls::crypto::{
    Aead, AeadAlg, Cipher, CipherAlg, GroupInfo, Hash, HashAlg, KeyId, KeyKind, KeyShare, Mac,
    PeerKey, Provider, Secret, SigalgInfo,
};
use rustyssl_tls::error::{Error, Result};

use crate::bn::BN_free;
use crate::bn::conv::BN_bin2bn;
use crate::err::{ERR_pop_to_mark, ERR_set_mark};
use crate::evp::asymcipher::{
    EVP_PKEY_decrypt, EVP_PKEY_decrypt_init, EVP_PKEY_encrypt, EVP_PKEY_encrypt_init,
};
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_set_padding,
    EVP_CipherFinal_ex, EVP_CipherInit_ex, EVP_CipherUpdate,
};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free};
use crate::evp::exchange::{EVP_PKEY_derive, EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer};
use crate::evp::kem::{
    EVP_PKEY_decapsulate, EVP_PKEY_decapsulate_init, EVP_PKEY_encapsulate,
    EVP_PKEY_encapsulate_init,
};
use crate::evp::keymgmt::{EVP_KEYMGMT_fetch, EVP_KEYMGMT_free, EVP_KEYMGMT_get0_provider};
use crate::evp::mac::{
    EVP_MAC_CTX_dup, EVP_MAC_CTX_free, EVP_MAC_CTX_new, EVP_MAC_fetch, EVP_MAC_final, EVP_MAC_free,
    EVP_MAC_init, EVP_MAC_update,
};
use crate::evp::md_ctx::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_copy_ex, EVP_MD_CTX_free,
    EVP_MD_CTX_new,
};
use crate::evp::pkey::params::EVP_PKEY_get_group_name;
use crate::evp::pkey::params::{
    EVP_PKEY_get1_encoded_public_key, EVP_PKEY_set1_encoded_public_key,
};
use crate::evp::pkey::{
    EVP_PKEY_free, EVP_PKEY_get_security_bits, EVP_PKEY_get_size, EVP_PKEY_is_a, EVP_PKEY_up_ref,
};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_name, EVP_PKEY_CTX_new_from_pkey,
    EVP_PKEY_CTX_set_params, EVP_PKEY_fromdata, EVP_PKEY_fromdata_init, EVP_PKEY_keygen,
    EVP_PKEY_keygen_init, EVP_PKEY_paramgen, EVP_PKEY_paramgen_init,
};
use crate::evp::setters::{
    EVP_PKEY_CTX_set_dh_pad, EVP_PKEY_CTX_set_group_name, EVP_PKEY_CTX_set_rsa_padding,
    EVP_PKEY_CTX_set_rsa_pss_saltlen,
};
use crate::evp::sigver::{
    EVP_DigestSign, EVP_DigestSignInit_ex, EVP_DigestVerify, EVP_DigestVerifyInit_ex,
};
use crate::mem;
use crate::objects::{OBJ_sn2nid, OBJ_txt2nid};
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_push_BN, OSSL_PARAM_BLD_to_param,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_size_t, OSSL_PARAM_construct_uint,
    OSSL_PARAM_construct_utf8_string, OSSL_PARAM_get_int, OSSL_PARAM_get_uint,
    OSSL_PARAM_locate_const,
};
use crate::provider::{OSSL_PROVIDER_do_all, OSSL_PROVIDER_get_capabilities};
use crate::rand_lib::{RAND_bytes_ex, RAND_priv_bytes_ex};
use crate::x509::cert::{X509_free, X509_get0_pubkey, decode_in};
use crate::x509::pubkey::d2i_PUBKEY_ex;

/// TLS 1.0 and 1.1's RSA signature over MD5 and SHA-1, which has no code point: OpenSSL's
/// `legacy_rsa_sigalg`, passed as this pseudo-scheme (the core's test provider uses the same).
pub(crate) const RSA_PKCS1_MD5_SHA1: u16 = 0xff01;

/// A failure inside the provider: OpenSSL reports these as internal errors (the EVP layer has
/// already raised its own error).
fn fail() -> Error {
    Error::internal()
}

/// A raw pointer that may move between threads with the object owning it: OpenSSL's contexts
/// and keys aren't tied to a thread, and each one here is used by one owner at a time.
struct Owned<T>(*mut T);

impl<T> Clone for Owned<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Owned<T> {}

// SAFETY: see `Owned`: the pointee is only used through its single owner.
unsafe impl<T> Send for Owned<T> {}
// SAFETY: as above; shared access happens under the registry's lock.
unsafe impl<T> Sync for Owned<T> {}

/// A group the providers offer, with what generating its keys needs.
#[derive(Clone)]
struct Group {
    info: GroupInfo,
    /// The key management algorithm (`TLS_GROUP_INFO.algorithm`).
    algorithm: CString,
    /// The group name given to the key generation (`realname`).
    realname: CString,
}

/// Where algorithms are fetched from: a library context and a property query.
#[derive(Clone)]
struct Env {
    libctx: Owned<OSSL_LIB_CTX>,
    propq: Option<CString>,
}

impl Env {
    /// The property query, or NULL.
    fn propq(&self) -> *const c_char {
        self.propq.as_ref().map_or(ptr::null(), |p| p.as_ptr())
    }

    /// The library context.
    fn libctx(&self) -> *mut OSSL_LIB_CTX {
        self.libctx.0
    }

    /// `ssl_generate_pkey_group`: a fresh key for the group.
    fn generate_group_key(&self, g: &Group) -> Result<Pkey> {
        // SAFETY: the library context; NUL-terminated names.
        let ctx = PkeyCtx(unsafe {
            EVP_PKEY_CTX_new_from_name(self.libctx(), g.algorithm.as_ptr(), self.propq())
        });
        if ctx.0.is_null() {
            return Err(fail());
        }
        // SAFETY: the context made above.
        if unsafe { EVP_PKEY_keygen_init(ctx.0) } <= 0 {
            return Err(fail());
        }
        // SAFETY: as above; the group's name.
        if unsafe { EVP_PKEY_CTX_set_group_name(ctx.0, g.realname.as_ptr()) } <= 0 {
            return Err(fail());
        }
        let mut pkey: *mut EVP_PKEY = ptr::null_mut();
        // SAFETY: as above; the slot.
        if unsafe { EVP_PKEY_keygen(ctx.0, &raw mut pkey) } <= 0 {
            // SAFETY: anything it made, or NULL.
            unsafe { EVP_PKEY_free(pkey) };
            return Err(fail());
        }
        Ok(Pkey(pkey))
    }

    /// `ssl_generate_param_group`: the group's parameters, as a key to hold a peer's share.
    fn param_group_key(&self, g: &Group) -> Result<Pkey> {
        // SAFETY: the library context; NUL-terminated names.
        let ctx = PkeyCtx(unsafe {
            EVP_PKEY_CTX_new_from_name(self.libctx(), g.algorithm.as_ptr(), self.propq())
        });
        if ctx.0.is_null() {
            return Err(fail());
        }
        // SAFETY: the context made above.
        if unsafe { EVP_PKEY_paramgen_init(ctx.0) } <= 0 {
            return Err(fail());
        }
        // SAFETY: as above; the group's name.
        if unsafe { EVP_PKEY_CTX_set_group_name(ctx.0, g.realname.as_ptr()) } <= 0 {
            return Err(fail());
        }
        let mut pkey: *mut EVP_PKEY = ptr::null_mut();
        // SAFETY: as above; the slot.
        if unsafe { EVP_PKEY_paramgen(ctx.0, &raw mut pkey) } <= 0 {
            // SAFETY: anything it made, or NULL.
            unsafe { EVP_PKEY_free(pkey) };
            return Err(fail());
        }
        Ok(Pkey(pkey))
    }

    /// A key of the group holding a peer's encoded share.
    fn peer_key(&self, g: &Group, encoded: &[u8]) -> Result<Pkey> {
        let k = self.param_group_key(g)?;
        // SAFETY: the key made above; the share's octets.
        if unsafe { EVP_PKEY_set1_encoded_public_key(k.0, encoded.as_ptr(), encoded.len()) } <= 0 {
            return Err(fail());
        }
        Ok(k)
    }

    /// `ssl_derive`: the shared secret of `own` with `peer`; a DH secret is padded to the
    /// prime's length.
    fn derive(&self, own: &Pkey, peer: &Pkey) -> Result<Secret> {
        // SAFETY: the library context; our key; the property query.
        let ctx =
            PkeyCtx(unsafe { EVP_PKEY_CTX_new_from_pkey(self.libctx(), own.0, self.propq()) });
        if ctx.0.is_null() {
            return Err(fail());
        }
        let mut len = 0usize;
        // SAFETY: the context made above.
        let ok = unsafe { EVP_PKEY_derive_init(ctx.0) } > 0
            // SAFETY: as above; the peer's key.
            && unsafe { EVP_PKEY_derive_set_peer(ctx.0, peer.0) } > 0
            // SAFETY: as above; a length only.
            && unsafe { EVP_PKEY_derive(ctx.0, ptr::null_mut(), &raw mut len) } > 0;
        if !ok {
            return Err(fail());
        }
        // SAFETY: our key; a NUL-terminated name.
        if unsafe { EVP_PKEY_is_a(own.0, c"DH".as_ptr()) } != 0 {
            // SAFETY: as above.
            unsafe { EVP_PKEY_CTX_set_dh_pad(ctx.0, 1) };
        }
        let mut out = vec![0u8; len];
        // SAFETY: as above; the room.
        if unsafe { EVP_PKEY_derive(ctx.0, out.as_mut_ptr(), &raw mut len) } <= 0 {
            // The peer's share was probably weak (`SSL_R_BAD_KEY_SHARE`, as ssl_derive says).
            return Err(Error::alert(
                rustyssl_abi::SSL_AD_ILLEGAL_PARAMETER,
                rustyssl_abi::SSL_R_BAD_KEY_SHARE,
            ));
        }
        out.truncate(len);
        Ok(Secret::new(out))
    }

    /// `ssl_decapsulate`: the KEM secret of the server's ciphertext with our key.
    fn decapsulate(&self, own: &Pkey, ct: &[u8]) -> Result<Secret> {
        // SAFETY: the library context; our key; the property query.
        let ctx =
            PkeyCtx(unsafe { EVP_PKEY_CTX_new_from_pkey(self.libctx(), own.0, self.propq()) });
        if ctx.0.is_null() {
            return Err(fail());
        }
        let mut len = 0usize;
        // SAFETY: the context made above.
        let ok = unsafe { EVP_PKEY_decapsulate_init(ctx.0, ptr::null()) } > 0
            // SAFETY: as above; a length only; the ciphertext.
            && unsafe { EVP_PKEY_decapsulate(ctx.0, ptr::null_mut(), &raw mut len, ct.as_ptr(), ct.len()) } > 0;
        if !ok {
            return Err(fail());
        }
        let mut out = vec![0u8; len];
        // SAFETY: as above; the room.
        if unsafe {
            EVP_PKEY_decapsulate(ctx.0, out.as_mut_ptr(), &raw mut len, ct.as_ptr(), ct.len())
        } <= 0
        {
            return Err(fail());
        }
        out.truncate(len);
        Ok(Secret::new(out))
    }

    /// `ssl_encapsulate`: a ciphertext and secret for the client's encapsulation key.
    fn encapsulate(&self, peer: &Pkey) -> Result<(Vec<u8>, Secret)> {
        // SAFETY: the library context; the client's key; the property query.
        let ctx =
            PkeyCtx(unsafe { EVP_PKEY_CTX_new_from_pkey(self.libctx(), peer.0, self.propq()) });
        if ctx.0.is_null() {
            return Err(fail());
        }
        let (mut ctlen, mut slen) = (0usize, 0usize);
        // SAFETY: the context made above.
        let ok = unsafe { EVP_PKEY_encapsulate_init(ctx.0, ptr::null()) } > 0
            // SAFETY: as above; lengths only.
            && unsafe { EVP_PKEY_encapsulate(ctx.0, ptr::null_mut(), &raw mut ctlen, ptr::null_mut(), &raw mut slen) } > 0
            && ctlen != 0
            && slen != 0;
        if !ok {
            return Err(fail());
        }
        let mut ct = vec![0u8; ctlen];
        let mut secret = vec![0u8; slen];
        // SAFETY: as above; the rooms.
        if unsafe {
            EVP_PKEY_encapsulate(
                ctx.0,
                ct.as_mut_ptr(),
                &raw mut ctlen,
                secret.as_mut_ptr(),
                &raw mut slen,
            )
        } <= 0
        {
            return Err(Error::alert(
                rustyssl_abi::SSL_AD_ILLEGAL_PARAMETER,
                rustyssl_abi::SSL_R_BAD_KEY_SHARE,
            ));
        }
        ct.truncate(ctlen);
        secret.truncate(slen);
        Ok((ct, Secret::new(secret)))
    }

    /// A DH key from explicit parameters (and a public value, for a peer).
    fn dh_key(&self, p: &[u8], g: &[u8], public: Option<&[u8]>) -> Result<Pkey> {
        let bld = ParamBld::new()?;
        let pb = Bn::from(p)?;
        let gb = Bn::from(g)?;
        // SAFETY: the builder; the prime, which outlives the parameters made below.
        let ok = unsafe { OSSL_PARAM_BLD_push_BN(bld.0, OSSL_PKEY_PARAM_FFC_P.as_ptr(), pb.0) } != 0
            // SAFETY: as above; the generator.
            && unsafe { OSSL_PARAM_BLD_push_BN(bld.0, OSSL_PKEY_PARAM_FFC_G.as_ptr(), gb.0) } != 0;
        if !ok {
            return Err(fail());
        }
        let pubb = match public {
            Some(v) => Some(Bn::from(v)?),
            None => None,
        };
        if let Some(pb) = &pubb {
            // SAFETY: as above; the public value.
            if unsafe { OSSL_PARAM_BLD_push_BN(bld.0, OSSL_PKEY_PARAM_PUB_KEY.as_ptr(), pb.0) } == 0
            {
                return Err(fail());
            }
        }
        // SAFETY: the builder.
        let params = unsafe { OSSL_PARAM_BLD_to_param(bld.0) };
        if params.is_null() {
            return Err(fail());
        }
        let params = Params(params);
        // SAFETY: the library context; a NUL-terminated name; the property query.
        let ctx = PkeyCtx(unsafe {
            EVP_PKEY_CTX_new_from_name(self.libctx(), c"DH".as_ptr(), self.propq())
        });
        if ctx.0.is_null() {
            return Err(fail());
        }
        let selection = if public.is_some() {
            EVP_PKEY_PUBLIC_KEY
        } else {
            EVP_PKEY_KEY_PARAMETERS
        };
        let mut pkey: *mut EVP_PKEY = ptr::null_mut();
        // SAFETY: the context made above.
        let ok = unsafe { EVP_PKEY_fromdata_init(ctx.0) } > 0
            // SAFETY: as above; the slot; the parameters.
            && unsafe { EVP_PKEY_fromdata(ctx.0, &raw mut pkey, selection, params.0) } > 0;
        if !ok {
            // SAFETY: anything it made, or NULL.
            unsafe { EVP_PKEY_free(pkey) };
            return Err(fail());
        }
        Ok(Pkey(pkey))
    }

    /// `ssl_generate_pkey`: a fresh key with `params`'s parameters.
    fn generate_from(&self, params: &Pkey) -> Result<Pkey> {
        // SAFETY: the library context; the parameters; the property query.
        let ctx =
            PkeyCtx(unsafe { EVP_PKEY_CTX_new_from_pkey(self.libctx(), params.0, self.propq()) });
        if ctx.0.is_null() {
            return Err(fail());
        }
        let mut pkey: *mut EVP_PKEY = ptr::null_mut();
        // SAFETY: the context made above.
        let ok = unsafe { EVP_PKEY_keygen_init(ctx.0) } > 0
            // SAFETY: as above; the slot.
            && unsafe { EVP_PKEY_keygen(ctx.0, &raw mut pkey) } > 0;
        if !ok {
            // SAFETY: anything it made, or NULL.
            unsafe { EVP_PKEY_free(pkey) };
            return Err(fail());
        }
        Ok(Pkey(pkey))
    }
}

/// The cryptography of one `SSL`, from its library context and property query.
pub(crate) struct EvpProvider {
    env: Env,
    /// The keys the core refers to by [`KeyId`] (each holding a reference).
    keys: Mutex<Vec<Owned<EVP_PKEY>>>,
    /// The groups, discovered on first use (`ssl_load_groups`).
    groups: Mutex<Option<Vec<Group>>>,
    /// The providers' signature algorithms, discovered on first use (`ssl_load_sigalgs`), each
    /// with its IANA name as `SSL_get0_peer_signature_name` hands it out. Set once and never
    /// replaced, so the names stay where they are while the provider lives.
    sigalgs: Mutex<Option<Vec<(SigalgInfo, CString)>>>,
    /// Which digests (by NID) and key types (by name) could be fetched, each asked once, as
    /// OpenSSL loads `ssl_digest_methods` once per context.
    available: Mutex<Vec<(Fetchable, bool)>>,
}

/// What [`EvpProvider`] remembers having tried to fetch.
#[derive(Clone, PartialEq, Eq)]
enum Fetchable {
    Digest(c_int),
    Keytype(String),
}

impl EvpProvider {
    /// A provider fetching from `libctx` (NULL: the default) with `propq` (NULL: none).
    ///
    /// # Safety
    /// `libctx` is NULL or a library context that outlives the provider; `propq` NULL or a
    /// NUL-terminated string.
    pub(crate) unsafe fn new(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> Self {
        let propq = if propq.is_null() {
            None
        } else {
            // SAFETY: the caller's string.
            Some(unsafe { CStr::from_ptr(propq) }.to_owned())
        };
        Self {
            env: Env {
                libctx: Owned(libctx),
                propq,
            },
            keys: Mutex::new(Vec::new()),
            groups: Mutex::new(None),
            sigalgs: Mutex::new(None),
            available: Mutex::new(Vec::new()),
        }
    }

    /// Whether `what` can be fetched, asked once (no lock is held while fetching, and the
    /// fetch's errors don't stay).
    fn fetchable(&self, what: Fetchable) -> bool {
        let known = self
            .available
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|(w, _)| *w == what)
            .map(|(_, ok)| *ok);
        if let Some(ok) = known {
            return ok;
        }
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        let ok = match &what {
            Fetchable::Digest(nid) => {
                // SAFETY: no pointers; a static name or NULL.
                let name = unsafe { crate::objects::OBJ_nid2sn(*nid) };
                !name.is_null()
                    && self
                        .fetch_md(
                            // SAFETY: a static NUL-terminated name.
                            unsafe { CStr::from_ptr(name) },
                        )
                        .is_ok()
            }
            Fetchable::Keytype(name) => CString::new(name.as_str()).is_ok_and(|n| {
                // SAFETY: the library context; a NUL-terminated name; the property query.
                let km = unsafe { EVP_KEYMGMT_fetch(self.libctx(), n.as_ptr(), self.propq()) };
                // SAFETY: fetched above, or NULL.
                unsafe { EVP_KEYMGMT_free(km) };
                !km.is_null()
            }),
        };
        // SAFETY: no preconditions.
        unsafe { ERR_pop_to_mark() };
        self.available
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((what, ok));
        ok
    }

    /// The providers' signature algorithms (TLS-SIGALG), discovered once. The discovery runs
    /// the providers' callbacks, so no lock is held during it.
    fn provider_sigalgs(&self) -> Vec<SigalgInfo> {
        let known = self
            .sigalgs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|l| l.iter().map(|(i, _)| i.clone()).collect());
        if let Some(list) = known {
            return list;
        }
        let mut d = Discovery {
            owner: self,
            provider: ptr::null(),
            groups: Vec::new(),
            sigalgs: Vec::new(),
        };
        // SAFETY: the library context; the callback and its data, which outlive the call.
        unsafe {
            OSSL_PROVIDER_do_all(
                self.libctx(),
                Some(discover_sigalgs_cb),
                ptr::from_mut(&mut d).cast(),
            )
        };
        let named = d
            .sigalgs
            .into_iter()
            .map(|i| {
                let name = CString::new(i.name.clone()).unwrap_or_default();
                (i, name)
            })
            .collect();
        let mut slot = self.sigalgs.lock().unwrap_or_else(PoisonError::into_inner);
        slot.get_or_insert(named)
            .iter()
            .map(|(i, _)| i.clone())
            .collect()
    }

    /// A provider signature algorithm's IANA name (valid while the provider lives) and hash
    /// NID, by code point (`tls1_lookup_sigalg` over the providers' part of the cache).
    pub(crate) fn provider_sigalg(&self, id: u16) -> Option<(*const c_char, c_int)> {
        self.provider_sigalgs();
        let slot = self.sigalgs.lock().unwrap_or_else(PoisonError::into_inner);
        slot.as_ref()?
            .iter()
            .find(|(i, _)| i.id == id)
            .map(|(i, n)| (n.as_ptr(), i.hash_nid))
    }

    /// The property query, or NULL.
    fn propq(&self) -> *const c_char {
        self.env.propq()
    }

    /// The library context.
    fn libctx(&self) -> *mut OSSL_LIB_CTX {
        self.env.libctx()
    }

    /// Registers `pkey` (taking a reference of its own) and returns its id; the same key gets
    /// the same id.
    ///
    /// # Safety
    /// `pkey` is a live key.
    pub(crate) unsafe fn add_key(&self, pkey: *mut EVP_PKEY) -> Option<KeyId> {
        let mut keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(i) = keys.iter().position(|k| k.0 == pkey) {
            return Some(KeyId(i));
        }
        // SAFETY: the caller's key.
        if unsafe { EVP_PKEY_up_ref(pkey) } == 0 {
            return None;
        }
        keys.push(Owned(pkey));
        Some(KeyId(keys.len().saturating_sub(1)))
    }

    /// A TLS 1.2 DHE server's key from its parameters and public value (`s->s3.peer_tmp`): a
    /// new key the caller owns, or `None`.
    pub(crate) fn peer_dh_key(&self, p: &[u8], g: &[u8], public: &[u8]) -> Option<*mut EVP_PKEY> {
        let k = self.env.dh_key(p, g, Some(public)).ok()?;
        let p = k.0;
        core::mem::forget(k);
        Some(p)
    }

    /// The peer's key share for group `id` as a key (`s->s3.peer_tmp`, which
    /// `SSL_get_peer_tmp_key` returns): a new key the caller owns, or `None` if the group or
    /// the share doesn't make one (a KEM's ciphertext, say).
    pub(crate) fn peer_share_key(&self, id: u16, share: &[u8]) -> Option<*mut EVP_PKEY> {
        let g = self.group(id).ok()?;
        let k = self.env.peer_key(&g, share).ok()?;
        let p = k.0;
        core::mem::forget(k);
        Some(p)
    }

    /// The key registered as `id`.
    fn key(&self, id: KeyId) -> Result<*mut EVP_PKEY> {
        let keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        keys.get(id.0).map(|k| k.0).ok_or_else(fail)
    }

    /// The groups, discovering them on first use.
    fn group_list(&self) -> Vec<Group> {
        let mut g = self.groups.lock().unwrap_or_else(PoisonError::into_inner);
        if g.is_none() {
            // Discovery calls into the providers, which don't call back into this SSL.
            *g = Some(self.discover_groups());
        }
        g.clone().unwrap_or_default()
    }

    /// `ssl_load_groups`: every provider's TLS-GROUP sets whose key management can be fetched
    /// (`add_provider_groups`), in the providers' order. Entries for a code point already
    /// listed (OpenSSL's aliases, such as `P-256` for `secp256r1`) become aliases of the first.
    fn discover_groups(&self) -> Vec<Group> {
        let mut d = Discovery {
            owner: self,
            provider: ptr::null(),
            groups: Vec::new(),
            sigalgs: Vec::new(),
        };
        // SAFETY: the library context; the callback and its data, which outlive the call.
        unsafe {
            OSSL_PROVIDER_do_all(
                self.libctx(),
                Some(discover_groups_cb),
                ptr::from_mut(&mut d).cast(),
            )
        };
        d.groups
    }

    /// The group with code point `id`.
    fn group(&self, id: u16) -> Result<Group> {
        self.group_list()
            .into_iter()
            .find(|g| g.info.id == id)
            .ok_or_else(fail)
    }

    /// A message digest by name, fetched.
    fn fetch_md(&self, name: &CStr) -> Result<Md> {
        // SAFETY: the library context; a NUL-terminated name; the property query.
        let md = unsafe { EVP_MD_fetch(self.libctx(), name.as_ptr(), self.propq()) };
        if md.is_null() {
            Err(fail())
        } else {
            Ok(Md(md))
        }
    }

    /// A MAC context: HMAC with `alg`, extra parameters, keyed with `key`.
    fn hmac_ctx(&self, alg: HashAlg, key: &[u8], tls_data_size: Option<usize>) -> Result<MacCtx> {
        // SAFETY: the library context; a NUL-terminated name; the property query.
        let mac = unsafe { EVP_MAC_fetch(self.libctx(), c"HMAC".as_ptr(), self.propq()) };
        if mac.is_null() {
            return Err(fail());
        }
        // SAFETY: the MAC fetched above; the context holds its own reference.
        let ctx = MacCtx(unsafe { EVP_MAC_CTX_new(mac) });
        // SAFETY: as above, released once.
        unsafe { EVP_MAC_free(mac) };
        if ctx.0.is_null() {
            return Err(fail());
        }
        let name = hash_name(alg);
        let mut size = tls_data_size.unwrap_or(0);
        let mut params: Vec<OSSL_PARAM> = Vec::with_capacity(3);
        // SAFETY: a static key; the name, which outlives the call below.
        params.push(unsafe {
            OSSL_PARAM_construct_utf8_string(
                OSSL_MAC_PARAM_DIGEST.as_ptr(),
                name.as_ptr().cast_mut(),
                0,
            )
        });
        if tls_data_size.is_some() {
            // SAFETY: a static key; the size, which outlives the call below.
            params.push(unsafe {
                OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_TLS_DATA_SIZE.as_ptr(), &raw mut size)
            });
        }
        // SAFETY: no preconditions.
        params.push(unsafe { OSSL_PARAM_construct_end() });
        // SAFETY: the context; the key's octets; the terminated parameters.
        if unsafe { EVP_MAC_init(ctx.0, key.as_ptr(), key.len(), params.as_ptr()) } <= 0 {
            return Err(fail());
        }
        Ok(ctx)
    }

    /// A key's signing or verifying context for `scheme`.
    ///
    /// # Safety
    /// `pkey` is a live key.
    unsafe fn sig_ctx(&self, pkey: *mut EVP_PKEY, scheme: u16, sign: bool) -> Result<MdCtx> {
        // A built-in scheme's digest, else a provider's (its capability's hash, `lu->hash`).
        let (mdname, pss) = match scheme_digest(scheme) {
            Ok((md, pss)) => (md.map_or(ptr::null(), CStr::as_ptr), pss),
            Err(e) => {
                let info = self.provider_sigalgs().into_iter().find(|i| i.id == scheme);
                let Some(info) = info else {
                    return Err(e);
                };
                let md = if info.hash_nid == rustyssl_abi::NID_undef {
                    ptr::null()
                } else {
                    // SAFETY: no pointers; an object's name lives with the object table.
                    unsafe { crate::objects::OBJ_nid2sn(info.hash_nid) }
                };
                (md, false)
            }
        };
        // SAFETY: no preconditions.
        let ctx = MdCtx(unsafe { EVP_MD_CTX_new() });
        if ctx.0.is_null() {
            return Err(fail());
        }
        let mut pctx: *mut EVP_PKEY_CTX = ptr::null_mut();
        let r = if sign {
            // SAFETY: the context; the slot; the digest's name or NULL; the library context;
            // the property query; the caller's key.
            unsafe {
                EVP_DigestSignInit_ex(
                    ctx.0,
                    &raw mut pctx,
                    mdname,
                    self.libctx(),
                    self.propq(),
                    pkey,
                    ptr::null(),
                )
            }
        } else {
            // SAFETY: as above.
            unsafe {
                EVP_DigestVerifyInit_ex(
                    ctx.0,
                    &raw mut pctx,
                    mdname,
                    self.libctx(),
                    self.propq(),
                    pkey,
                    ptr::null(),
                )
            }
        };
        if r <= 0 {
            return Err(fail());
        }
        if pss {
            // SAFETY: the key's context, which the digest context owns.
            let ok = unsafe { EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) } > 0
                // SAFETY: as above.
                && unsafe { EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) } > 0;
            if !ok {
                return Err(fail());
            }
        }
        Ok(ctx)
    }

    /// The public key of a certificate's DER, decoded in the provider's library context.
    fn cert_key(&self, cert: &[u8]) -> Result<(KeyOwner, *mut EVP_PKEY)> {
        let len = core::ffi::c_long::try_from(cert.len()).map_err(|_| fail())?;
        // A certificate, or (for a raw public key) a SubjectPublicKeyInfo.
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: the library context and the property query, alive with the provider.
        let x = X509Ptr(unsafe { decode_in(cert, self.libctx(), self.propq()) });
        // SAFETY: no preconditions.
        unsafe { ERR_pop_to_mark() };
        if !x.0.is_null() {
            // SAFETY: the certificate decoded above; the key stays its own.
            let pkey = unsafe { X509_get0_pubkey(x.0) };
            if pkey.is_null() {
                return Err(fail());
            }
            return Ok((KeyOwner::Cert(x), pkey));
        }
        let mut p = cert.as_ptr();
        // SAFETY: the key's octets.
        let k = PkeyPtr(unsafe {
            d2i_PUBKEY_ex(
                ptr::null_mut(),
                &raw mut p,
                len,
                self.libctx(),
                self.propq(),
            )
        });
        if k.0.is_null() {
            return Err(fail());
        }
        let pkey = k.0;
        Ok((KeyOwner::Key(k), pkey))
    }
}

impl Drop for EvpProvider {
    fn drop(&mut self) {
        let keys = self.keys.get_mut().unwrap_or_else(PoisonError::into_inner);
        for k in keys.drain(..) {
            // SAFETY: the reference `add_key` took, released once.
            unsafe { EVP_PKEY_free(k.0) };
        }
    }
}

/// What group and sigalg discovery collects.
struct Discovery<'a> {
    owner: &'a EvpProvider,
    /// The provider whose capabilities are being read (`provider_ctx_data_st`'s `provider`).
    provider: *const OSSL_PROVIDER,
    groups: Vec<Group>,
    sigalgs: Vec<SigalgInfo>,
}

/// A UTF-8 parameter's string.
///
/// # Safety
/// `params` is a terminated parameter array.
unsafe fn param_str(params: *const OSSL_PARAM, key: &CStr) -> Option<CString> {
    // SAFETY: the caller's array; a NUL-terminated key.
    let p = unsafe { OSSL_PARAM_locate_const(params, key.as_ptr()) };
    // SAFETY: the parameter found, or NULL.
    let p = unsafe { p.as_ref() }?;
    if p.data_type != OSSL_PARAM_UTF8_STRING.cast_unsigned() || p.data.is_null() {
        return None;
    }
    // SAFETY: a UTF-8 string parameter's NUL-terminated data (as the providers make them).
    Some(unsafe { CStr::from_ptr(p.data.cast::<c_char>()) }.to_owned())
}

/// An unsigned parameter.
///
/// # Safety
/// `params` is a terminated parameter array.
unsafe fn param_uint(params: *const OSSL_PARAM, key: &CStr) -> Option<c_uint> {
    // SAFETY: the caller's array; a NUL-terminated key.
    let p = unsafe { OSSL_PARAM_locate_const(params, key.as_ptr()) };
    if p.is_null() {
        return None;
    }
    let mut v: c_uint = 0;
    // SAFETY: the parameter; the room.
    (unsafe { OSSL_PARAM_get_uint(p, &raw mut v) } != 0).then_some(v)
}

/// A signed parameter.
///
/// # Safety
/// `params` is a terminated parameter array.
unsafe fn param_int(params: *const OSSL_PARAM, key: &CStr) -> Option<c_int> {
    // SAFETY: the caller's array; a NUL-terminated key.
    let p = unsafe { OSSL_PARAM_locate_const(params, key.as_ptr()) };
    if p.is_null() {
        return None;
    }
    let mut v: c_int = 0;
    // SAFETY: the parameter; the room.
    (unsafe { OSSL_PARAM_get_int(p, &raw mut v) } != 0).then_some(v)
}

/// `add_provider_groups`: one TLS-GROUP set, kept if its key management can be fetched.
/// Malformed sets fail (`ERR_R_PASSED_INVALID_ARGUMENT`), as in OpenSSL.
///
/// # Safety
/// `params` is a terminated parameter array; `arg` a live [`Discovery`].
unsafe extern "C" fn add_group_cb(params: *const OSSL_PARAM, arg: *mut c_void) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { arg.cast::<Discovery<'_>>().as_mut() }) else {
        return 0;
    };
    // SAFETY: the caller's array.
    let name_p = unsafe { param_str(params, OSSL_CAPABILITY_TLS_GROUP_NAME) };
    // SAFETY: the caller's array.
    let realname_p = unsafe { param_str(params, OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL) };
    // SAFETY: the caller's array.
    let gid_p = unsafe { param_uint(params, OSSL_CAPABILITY_TLS_GROUP_ID) };
    // SAFETY: the caller's array.
    let alg_p = unsafe { param_str(params, OSSL_CAPABILITY_TLS_GROUP_ALG) };
    // SAFETY: the caller's array.
    let bits_p = unsafe { param_uint(params, OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS) };
    let fields = (name_p, realname_p, gid_p, alg_p, bits_p);
    let (Some(name), Some(realname), Some(gid), Some(algorithm), Some(secbits)) = fields else {
        crate::err::raise(
            rustyssl_abi::ERR_LIB_SSL,
            rustyssl_abi::ERR_R_PASSED_INVALID_ARGUMENT,
            "add_provider_groups",
        );
        return 0;
    };
    let Ok(id) = u16::try_from(gid) else {
        crate::err::raise(
            rustyssl_abi::ERR_LIB_SSL,
            rustyssl_abi::ERR_R_PASSED_INVALID_ARGUMENT,
            "add_provider_groups",
        );
        return 0;
    };
    // SAFETY: as above.
    let kem_param =
        unsafe { OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_GROUP_IS_KEM.as_ptr()) };
    let is_kem = if kem_param.is_null() {
        0
    } else {
        // SAFETY: as above.
        match unsafe { param_uint(params, OSSL_CAPABILITY_TLS_GROUP_IS_KEM) } {
            Some(v @ 0..=1) => v,
            _ => {
                crate::err::raise(
                    rustyssl_abi::ERR_LIB_SSL,
                    rustyssl_abi::ERR_R_PASSED_INVALID_ARGUMENT,
                    "add_provider_groups",
                );
                return 0;
            }
        }
    };
    // SAFETY: the caller's array.
    let min_tls_p = unsafe { param_int(params, OSSL_CAPABILITY_TLS_GROUP_MIN_TLS) };
    // SAFETY: the caller's array.
    let max_tls_p = unsafe { param_int(params, OSSL_CAPABILITY_TLS_GROUP_MAX_TLS) };
    // SAFETY: the caller's array.
    let min_dtls_p = unsafe { param_int(params, OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS) };
    // SAFETY: the caller's array.
    let max_dtls_p = unsafe { param_int(params, OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS) };
    let versions = (min_tls_p, max_tls_p, min_dtls_p, max_dtls_p);
    let (Some(min_tls), Some(max_tls), Some(min_dtls), Some(max_dtls)) = versions else {
        crate::err::raise(
            rustyssl_abi::ERR_LIB_SSL,
            rustyssl_abi::ERR_R_PASSED_INVALID_ARGUMENT,
            "add_provider_groups",
        );
        return 0;
    };
    // The group counts only if its algorithm can be fetched under the property query, from
    // this provider; either way the set was processed.
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: the library context; NUL-terminated names.
    let km = unsafe { EVP_KEYMGMT_fetch(d.owner.libctx(), algorithm.as_ptr(), d.owner.propq()) };
    // SAFETY: fetched above, or NULL.
    let usable = !km.is_null() && unsafe { EVP_KEYMGMT_get0_provider(km) } == d.provider;
    // SAFETY: fetched above, or NULL.
    unsafe { EVP_KEYMGMT_free(km) };
    // SAFETY: no preconditions.
    unsafe { ERR_pop_to_mark() };
    if !usable {
        return 1;
    }
    let tls_name = name.to_string_lossy().into_owned();
    if let Some(first) = d.groups.iter_mut().find(|g| g.info.id == id) {
        first.info.aliases.push(tls_name);
        return 1;
    }
    d.groups.push(Group {
        info: GroupInfo {
            name: tls_name,
            internal_name: realname.to_string_lossy().into_owned(),
            aliases: Vec::new(),
            id,
            security_bits: secbits,
            min_tls,
            max_tls,
            min_dtls,
            max_dtls,
            is_kem: is_kem == 1,
            algorithm: algorithm.to_string_lossy().into_owned(),
        },
        algorithm,
        realname,
    });
    1
}

/// `discover_provider_groups`.
///
/// # Safety
/// `prov` is a live provider; `arg` a live [`Discovery`].
unsafe extern "C" fn discover_groups_cb(prov: *mut OSSL_PROVIDER, arg: *mut c_void) -> c_int {
    // SAFETY: the caller's guarantee.
    if let Some(d) = unsafe { arg.cast::<Discovery<'_>>().as_mut() } {
        d.provider = prov.cast_const();
    }
    // SAFETY: the caller's provider; the callback and its data. No lock is held.
    unsafe { OSSL_PROVIDER_get_capabilities(prov, c"TLS-GROUP".as_ptr(), Some(add_group_cb), arg) }
}

/// One TLS-SIGALG set (`add_provider_sigalgs`): its mandatory parameters checked (a missing or
/// mistyped one fails the discovery with `ERR_R_PASSED_INVALID_ARGUMENT`, a mistyped optional one
/// without an entry), its TLS versions normalized (provider sigalgs are TLS 1.3's only; none in
/// DTLS), and the set taken only if its key type's key manager comes from this provider, with
/// its objects created (`OBJ_create`, `OBJ_add_sigid`) as OpenSSL creates them. The lookups
/// leave no errors behind (an error mark).
///
/// # Safety
/// `params` is a terminated parameter array; `arg` a live [`Discovery`].
unsafe extern "C" fn add_sigalg_cb(params: *const OSSL_PARAM, arg: *mut c_void) -> c_int {
    use crate::objects::sigid::OBJ_add_sigid;
    use crate::objects::{OBJ_create, OBJ_nid2obj, OBJ_txt2nid};
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { arg.cast::<Discovery<'_>>().as_mut() }) else {
        return 0;
    };
    let invalid = || {
        crate::err::raise(
            rustyssl_abi::ERR_LIB_SSL,
            rustyssl_abi::ERR_R_PASSED_INVALID_ARGUMENT,
            "add_provider_sigalgs",
        );
        0
    };
    // A UTF-8 parameter: absent (`Ok(None)`), present (`Ok(Some)`), or of another type (`Err`).
    let optional = |key: &CStr| -> core::result::Result<Option<CString>, ()> {
        // SAFETY: the caller's array; a NUL-terminated key.
        let p = unsafe { OSSL_PARAM_locate_const(params, key.as_ptr()) };
        if p.is_null() {
            return Ok(None);
        }
        // SAFETY: the caller's array.
        unsafe { param_str(params, key) }.map(Some).ok_or(())
    };
    // The mandatory parameters.
    // SAFETY: the caller's array.
    let Some(sigalg_name) = (unsafe { param_str(params, OSSL_CAPABILITY_TLS_SIGALG_NAME) }) else {
        return invalid();
    };
    // SAFETY: as above.
    let Some(name) = (unsafe { param_str(params, OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME) }) else {
        return invalid();
    };
    // SAFETY: as above.
    let code_point = unsafe { param_uint(params, OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT) };
    let Some(id) = code_point.and_then(|cp| u16::try_from(cp).ok()) else {
        return invalid();
    };
    // SAFETY: as above.
    let Some(bits) = (unsafe { param_uint(params, OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS) })
    else {
        return invalid();
    };
    // The optional ones: a value of the wrong type fails the discovery, with no entry.
    let optionals = (
        optional(OSSL_CAPABILITY_TLS_SIGALG_OID),
        optional(OSSL_CAPABILITY_TLS_SIGALG_SIG_NAME),
        optional(OSSL_CAPABILITY_TLS_SIGALG_SIG_OID),
        optional(OSSL_CAPABILITY_TLS_SIGALG_HASH_NAME),
        optional(OSSL_CAPABILITY_TLS_SIGALG_HASH_OID),
        optional(OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE),
        optional(OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE_OID),
    );
    let (
        Ok(sigalg_oid),
        Ok(sig_name),
        Ok(sig_oid),
        Ok(hash_name),
        Ok(hash_oid),
        Ok(keytype),
        Ok(keytype_oid),
    ) = optionals
    else {
        return 0;
    };
    // The DTLS versions (optional, "not documented prior to 3.5"): checked, then dropped, as no
    // provider sigalg is used in DTLS.
    let mut dtls = [-1; 2];
    for (key, slot) in [
        OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS,
        OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS,
    ]
    .into_iter()
    .zip(dtls.iter_mut())
    {
        // SAFETY: as above.
        if unsafe { OSSL_PARAM_locate_const(params, key.as_ptr()) }.is_null() {
            continue;
        }
        // SAFETY: as above.
        let Some(v) = (unsafe { param_int(params, key) }) else {
            return invalid();
        };
        *slot = v;
    }
    let [min_dtls, max_dtls] = dtls;
    // DTLS version numbers grow downward.
    if max_dtls != 0 && max_dtls != -1 && max_dtls > min_dtls {
        return invalid();
    }
    // The TLS versions, mandatory again.
    // SAFETY: as above.
    let Some(mut min_tls) = (unsafe { param_int(params, OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS) })
    else {
        return invalid();
    };
    // SAFETY: as above.
    let Some(mut max_tls) = (unsafe { param_int(params, OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS) })
    else {
        return invalid();
    };
    if max_tls != 0 && max_tls != -1 && max_tls < min_tls {
        return invalid();
    }
    let tls13 = rustyssl_abi::TLS1_3_VERSION;
    if (min_tls != 0 && min_tls != -1 && min_tls > tls13)
        || (max_tls != 0 && max_tls != -1 && max_tls < tls13)
    {
        (min_tls, max_tls) = (-1, -1);
    }
    // An unusable one is processed but not taken.
    if min_tls == -1 {
        return 1;
    }
    let c = |s: &Option<CString>| s.as_ref().map_or(ptr::null(), |s| s.as_ptr());
    // `inferred_keytype`: the key type, else the signature algorithm's, else the sigalg's name.
    let key_type = keytype
        .clone()
        .or_else(|| sig_name.clone())
        .unwrap_or_else(|| sigalg_name.clone());
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: the library context; NUL-terminated names.
    let km = unsafe { EVP_KEYMGMT_fetch(d.owner.libctx(), key_type.as_ptr(), d.owner.propq()) };
    // SAFETY: fetched above, or NULL.
    let ours = !km.is_null() && unsafe { EVP_KEYMGMT_get0_provider(km) } == d.provider;
    // SAFETY: fetched above, or NULL.
    unsafe { EVP_KEYMGMT_free(km) };
    let mut taken = None;
    if ours {
        // Registered here unless the provider registered it already; the result doesn't
        // matter.
        // SAFETY: NULL or NUL-terminated strings.
        unsafe { OBJ_create(c(&sigalg_oid), sigalg_name.as_ptr(), ptr::null()) };
        // SAFETY: a NUL-terminated name.
        let sig_nid = unsafe { OBJ_txt2nid(sigalg_name.as_ptr()) };
        // SAFETY: no pointers.
        let registered =
            sig_nid != rustyssl_abi::NID_undef && !unsafe { OBJ_nid2obj(sig_nid) }.is_null();
        if registered {
            for (oid, n) in [
                (&sig_oid, &sig_name),
                (&keytype_oid, &keytype),
                (&hash_oid, &hash_name),
            ] {
                if let Some(n) = n {
                    // SAFETY: as above.
                    unsafe { OBJ_create(c(oid), n.as_ptr(), ptr::null()) };
                }
            }
            let hash_nid = hash_name.as_ref().map_or(rustyssl_abi::NID_undef, |h| {
                // SAFETY: a NUL-terminated name.
                unsafe { OBJ_txt2nid(h.as_ptr()) }
            });
            // SAFETY: as above.
            let key_nid = unsafe { OBJ_txt2nid(key_type.as_ptr()) };
            // SAFETY: no pointers.
            unsafe { OBJ_add_sigid(sig_nid, hash_nid, key_nid) };
            taken = Some((sig_nid, hash_nid));
        }
    }
    // SAFETY: no preconditions.
    unsafe { ERR_pop_to_mark() };
    let Some((sig_nid, hash_nid)) = taken else {
        // Not this provider's: processed. This provider's, but its name names no object: the
        // sanity check fails, raising its error, and the discovery goes on.
        if ours {
            invalid();
        }
        return 1;
    };
    d.sigalgs.push(SigalgInfo {
        sig_nid,
        hash_nid,
        key_type: key_type.to_string_lossy().into_owned(),
        name: name.to_string_lossy().into_owned(),
        id,
        security_bits: bits,
        min_tls,
        max_tls,
    });
    1
}

/// `discover_provider_sigalgs`.
///
/// # Safety
/// `prov` is a live provider; `arg` a live [`Discovery`].
unsafe extern "C" fn discover_sigalgs_cb(prov: *mut OSSL_PROVIDER, arg: *mut c_void) -> c_int {
    // SAFETY: the caller's guarantee.
    if let Some(d) = unsafe { arg.cast::<Discovery<'_>>().as_mut() } {
        d.provider = prov.cast_const();
    }
    // SAFETY: the caller's provider; the callback and its data. No lock is held.
    unsafe {
        OSSL_PROVIDER_get_capabilities(prov, c"TLS-SIGALG".as_ptr(), Some(add_sigalg_cb), arg)
    }
}

/// A hash's EVP name.
pub(crate) fn hash_name(alg: HashAlg) -> &'static CStr {
    match alg {
        HashAlg::Md5Sha1 => c"MD5-SHA1",
        HashAlg::Md5 => c"MD5",
        HashAlg::Sha1 => c"SHA1",
        HashAlg::Sha224 => c"SHA224",
        HashAlg::Sha256 => c"SHA256",
        HashAlg::Sha384 => c"SHA384",
        HashAlg::Sha512 => c"SHA512",
        HashAlg::Sm3 => c"SM3",
    }
}

/// A signature scheme's digest (`None`: the algorithm hashes itself) and whether it is PSS.
fn scheme_digest(scheme: u16) -> Result<(Option<&'static CStr>, bool)> {
    use sigscheme as s;
    Ok(match scheme {
        RSA_PKCS1_MD5_SHA1 => (Some(c"MD5-SHA1"), false),
        s::RSA_PKCS1_SHA1 | s::ECDSA_SHA1 | s::DSA_SHA1 => (Some(c"SHA1"), false),
        s::RSA_PKCS1_SHA224 | s::ECDSA_SHA224 | s::DSA_SHA224 => (Some(c"SHA224"), false),
        s::RSA_PKCS1_SHA256
        | s::ECDSA_SECP256R1_SHA256
        | s::DSA_SHA256
        | s::ECDSA_BRAINPOOLP256R1_SHA256 => (Some(c"SHA256"), false),
        s::RSA_PKCS1_SHA384
        | s::ECDSA_SECP384R1_SHA384
        | s::DSA_SHA384
        | s::ECDSA_BRAINPOOLP384R1_SHA384 => (Some(c"SHA384"), false),
        s::RSA_PKCS1_SHA512
        | s::ECDSA_SECP521R1_SHA512
        | s::DSA_SHA512
        | s::ECDSA_BRAINPOOLP512R1_SHA512 => (Some(c"SHA512"), false),
        s::RSA_PSS_RSAE_SHA256 | s::RSA_PSS_PSS_SHA256 => (Some(c"SHA256"), true),
        s::RSA_PSS_RSAE_SHA384 | s::RSA_PSS_PSS_SHA384 => (Some(c"SHA384"), true),
        s::RSA_PSS_RSAE_SHA512 | s::RSA_PSS_PSS_SHA512 => (Some(c"SHA512"), true),
        s::ED25519 | s::ED448 | s::MLDSA44 | s::MLDSA65 | s::MLDSA87 => (None, false),
        _ => return Err(fail()),
    })
}

/// An AEAD's EVP name.
fn aead_name(alg: AeadAlg) -> &'static CStr {
    match alg {
        AeadAlg::Aes128Gcm => c"AES-128-GCM",
        AeadAlg::Aes256Gcm => c"AES-256-GCM",
        AeadAlg::ChaCha20Poly1305 => c"ChaCha20-Poly1305",
        AeadAlg::Aes128Ccm | AeadAlg::Aes128Ccm8 => c"AES-128-CCM",
        AeadAlg::Aes256Ccm | AeadAlg::Aes256Ccm8 => c"AES-256-CCM",
        AeadAlg::Aria128Gcm => c"ARIA-128-GCM",
        AeadAlg::Aria256Gcm => c"ARIA-256-GCM",
        AeadAlg::Sm4Gcm => c"SM4-GCM",
        AeadAlg::Sm4Ccm => c"SM4-CCM",
    }
}

/// Whether an AEAD is CCM (the tag length and message length come first).
fn is_ccm(alg: AeadAlg) -> bool {
    matches!(
        alg,
        AeadAlg::Aes128Ccm
            | AeadAlg::Aes256Ccm
            | AeadAlg::Aes128Ccm8
            | AeadAlg::Aes256Ccm8
            | AeadAlg::Sm4Ccm
    )
}

/// A CBC cipher's EVP name (`None` for no encryption).
fn cipher_name(alg: CipherAlg) -> Option<&'static CStr> {
    Some(match alg {
        CipherAlg::Aes128Cbc => c"AES-128-CBC",
        CipherAlg::Aes256Cbc => c"AES-256-CBC",
        CipherAlg::Camellia128Cbc => c"CAMELLIA-128-CBC",
        CipherAlg::Camellia256Cbc => c"CAMELLIA-256-CBC",
        CipherAlg::Aria128Cbc => c"ARIA-128-CBC",
        CipherAlg::Aria256Cbc => c"ARIA-256-CBC",
        CipherAlg::DesEde3Cbc => c"DES-EDE3-CBC",
        CipherAlg::SeedCbc => c"SEED-CBC",
        CipherAlg::Sm4Cbc => c"SM4-CBC",
        CipherAlg::Null => return None,
    })
}

/// An `int` length for EVP's cipher calls.
fn int_len(n: usize) -> Result<c_int> {
    c_int::try_from(n).map_err(|_| fail())
}

macro_rules! owner {
    ($(#[$doc:meta])* $name:ident($ty:ty) = $free:expr) => {
        $(#[$doc])*
        struct $name(*mut $ty);

        // SAFETY: the object is used by its single owner only (see `Owned`).
        unsafe impl Send for $name {}

        impl Drop for $name {
            fn drop(&mut self) {
                // SAFETY: the object owned, or NULL, released once.
                unsafe { $free(self.0) };
            }
        }
    };
}

owner!(
    /// An owned `EVP_PKEY`.
    Pkey(EVP_PKEY) = EVP_PKEY_free
);
owner!(
    /// An owned `EVP_PKEY_CTX`.
    PkeyCtx(EVP_PKEY_CTX) = EVP_PKEY_CTX_free
);
owner!(
    /// An owned `EVP_MD_CTX`.
    MdCtx(EVP_MD_CTX) = EVP_MD_CTX_free
);
owner!(
    /// An owned `EVP_MD`.
    Md(EVP_MD) = EVP_MD_free
);
owner!(
    /// An owned `EVP_MAC_CTX`.
    MacCtx(EVP_MAC_CTX) = EVP_MAC_CTX_free
);
owner!(
    /// An owned `EVP_CIPHER`.
    CipherPtr(EVP_CIPHER) = EVP_CIPHER_free
);
owner!(
    /// An owned `EVP_CIPHER_CTX`.
    CipherCtx(EVP_CIPHER_CTX) = EVP_CIPHER_CTX_free
);
owner!(
    /// An owned `X509`.
    X509Ptr(rustyssl_abi::X509) = X509_free
);
owner!(
    /// An owned `EVP_PKEY`.
    PkeyPtr(EVP_PKEY) = EVP_PKEY_free
);

/// What keeps a peer's public key alive: its certificate, or the key itself (a raw public key).
enum KeyOwner {
    /// The certificate the key belongs to.
    Cert(X509Ptr),
    /// The key, decoded from a SubjectPublicKeyInfo.
    Key(PkeyPtr),
}
owner!(
    /// An owned `OSSL_PARAM_BLD`.
    ParamBld(rustyssl_abi::OSSL_PARAM_BLD) = OSSL_PARAM_BLD_free
);
owner!(
    /// An owned parameter array (`OSSL_PARAM_free`).
    Params(OSSL_PARAM) = OSSL_PARAM_free
);
owner!(
    /// An owned `BIGNUM`.
    Bn(rustyssl_abi::BIGNUM) = BN_free
);

impl ParamBld {
    fn new() -> Result<Self> {
        // SAFETY: no preconditions.
        let b = unsafe { OSSL_PARAM_BLD_new() };
        if b.is_null() {
            Err(fail())
        } else {
            Ok(Self(b))
        }
    }
}

impl Bn {
    /// A big-endian unsigned number.
    fn from(v: &[u8]) -> Result<Self> {
        let len = int_len(v.len())?;
        // SAFETY: the octets; a new number.
        let b = unsafe { BN_bin2bn(v.as_ptr(), len, ptr::null_mut()) };
        if b.is_null() {
            Err(fail())
        } else {
            Ok(Self(b))
        }
    }
}

/// An incremental digest.
struct EvpHash(MdCtx);

impl EvpHash {
    /// A copy of the state.
    fn copy(&self) -> Option<MdCtx> {
        // SAFETY: no preconditions.
        let c = MdCtx(unsafe { EVP_MD_CTX_new() });
        if c.0.is_null() {
            return None;
        }
        // SAFETY: both contexts live.
        (unsafe { EVP_MD_CTX_copy_ex(c.0, self.0.0) } != 0).then_some(c)
    }
}

impl Hash for EvpHash {
    fn update(&mut self, data: &[u8]) {
        // SAFETY: the context; the data. A failure shows when the hash is read.
        unsafe { EVP_DigestUpdate(self.0.0, data.as_ptr().cast(), data.len()) };
    }

    fn current(&self) -> Vec<u8> {
        let Some(c) = self.copy() else {
            return Vec::new();
        };
        let mut out = vec![0u8; 64];
        let mut n: c_uint = 0;
        // SAFETY: the copy; room for any digest; the length's slot.
        if unsafe { EVP_DigestFinal_ex(c.0, out.as_mut_ptr(), &raw mut n) } == 0 {
            return Vec::new();
        }
        out.truncate(usize::try_from(n).unwrap_or(0));
        out
    }

    fn fork(&self) -> Box<dyn Hash> {
        match self.copy() {
            Some(c) => Box::new(EvpHash(c)),
            None => Box::new(EvpHash(MdCtx(ptr::null_mut()))),
        }
    }

    fn finish(self: Box<Self>) -> Vec<u8> {
        let mut out = vec![0u8; 64];
        let mut n: c_uint = 0;
        // SAFETY: the context; room for any digest; the length's slot.
        if unsafe { EVP_DigestFinal_ex(self.0.0, out.as_mut_ptr(), &raw mut n) } == 0 {
            return Vec::new();
        }
        out.truncate(usize::try_from(n).unwrap_or(0));
        out
    }
}

/// An HMAC, re-keyed after each tag from a pristine copy.
struct EvpMac {
    template: MacCtx,
    ctx: MacCtx,
}

impl Mac for EvpMac {
    fn update(&mut self, data: &[u8]) {
        // SAFETY: the context; the data. A failure shows as an empty tag.
        unsafe { EVP_MAC_update(self.ctx.0, data.as_ptr(), data.len()) };
    }

    fn finish(&mut self) -> Vec<u8> {
        let mut out = vec![0u8; 64];
        let mut n = 0usize;
        // SAFETY: the context; room for any HMAC.
        let ok = unsafe { EVP_MAC_final(self.ctx.0, out.as_mut_ptr(), &raw mut n, out.len()) } != 0;
        // SAFETY: the pristine copy.
        self.ctx = MacCtx(unsafe { EVP_MAC_CTX_dup(self.template.0) });
        if !ok {
            return Vec::new();
        }
        out.truncate(n);
        out
    }
}

/// An AEAD: a fresh cipher context per record, as each record has its own nonce.
struct EvpAead {
    cipher: CipherPtr,
    alg: AeadAlg,
    key: Secret,
}

impl EvpAead {
    /// Runs the AEAD one way over `data` (`seal`: append the tag; `open`: check and strip it).
    fn run(&mut self, nonce: &[u8], aad: &[u8], data: &mut Vec<u8>, encrypt: bool) -> Result<()> {
        let tag_len = self.alg.tag_len();
        let enc = c_int::from(encrypt);
        let mut tag = vec![0u8; tag_len];
        if !encrypt {
            let Some(body_len) = data.len().checked_sub(tag_len) else {
                return Err(bad_mac());
            };
            tag = data.split_off(body_len);
        }
        // SAFETY: no preconditions.
        let ctx = CipherCtx(unsafe { EVP_CIPHER_CTX_new() });
        if ctx.0.is_null() {
            return Err(fail());
        }
        let ivlen = int_len(nonce.len())?;
        let tlen = int_len(tag_len)?;
        // SAFETY: the context; the fetched cipher; no key or IV yet.
        let mut ok = unsafe { EVP_CipherInit_ex(ctx.0, self.cipher.0, ptr::null_mut(), ptr::null(), ptr::null(), enc) } != 0
            // SAFETY: as above.
            && unsafe { EVP_CIPHER_CTX_ctrl(ctx.0, EVP_CTRL_AEAD_SET_IVLEN, ivlen, ptr::null_mut()) } > 0;
        if ok && is_ccm(self.alg) {
            let tag_ptr = if encrypt {
                ptr::null_mut()
            } else {
                tag.as_mut_ptr().cast()
            };
            // SAFETY: as above; the expected tag (decrypting) or none.
            ok = unsafe { EVP_CIPHER_CTX_ctrl(ctx.0, EVP_CTRL_AEAD_SET_TAG, tlen, tag_ptr) } > 0;
        }
        // SAFETY: as above; the key; the nonce.
        ok = ok
            && unsafe {
                EVP_CipherInit_ex(
                    ctx.0,
                    ptr::null(),
                    ptr::null_mut(),
                    self.key.bytes().as_ptr(),
                    nonce.as_ptr(),
                    enc,
                )
            } != 0;
        if ok && !encrypt && !is_ccm(self.alg) {
            // The expected tag before any data, as `tls13_cipher` gives it: a provider that
            // decrypts in one operation (PKCS#11's) needs it first.
            // SAFETY: as above; the expected tag.
            ok = unsafe {
                EVP_CIPHER_CTX_ctrl(ctx.0, EVP_CTRL_AEAD_SET_TAG, tlen, tag.as_mut_ptr().cast())
            } > 0;
        }
        let dlen = int_len(data.len())?;
        let mut outl: c_int = 0;
        if ok && is_ccm(self.alg) {
            // SAFETY: as above: CCM's total length first.
            ok = unsafe {
                EVP_CipherUpdate(ctx.0, ptr::null_mut(), &raw mut outl, ptr::null(), dlen)
            } != 0;
        }
        let alen = int_len(aad.len())?;
        // SAFETY: as above; the additional data.
        ok = ok
            && unsafe {
                EVP_CipherUpdate(ctx.0, ptr::null_mut(), &raw mut outl, aad.as_ptr(), alen)
            } != 0;
        let mut out = vec![0u8; data.len().saturating_add(16)];
        // What the AAD's update reported isn't output.
        outl = 0;
        // CCM authenticates in this update, so it runs for an empty record too: skipping it
        // would take the record unverified.
        if ok && (!data.is_empty() || is_ccm(self.alg)) {
            // SAFETY: as above; room for the data and a block.
            ok = unsafe {
                EVP_CipherUpdate(ctx.0, out.as_mut_ptr(), &raw mut outl, data.as_ptr(), dlen)
            } != 0;
        }
        let done = usize::try_from(outl).unwrap_or(0);
        let mut fin: c_int = 0;
        let rest = out
            .get_mut(done..)
            .map_or(ptr::null_mut(), <[u8]>::as_mut_ptr);
        // CCM verified its tag in the update; GCM and ChaCha20-Poly1305 do in the final.
        if ok && !(is_ccm(self.alg) && !encrypt) {
            // SAFETY: as above; the room left.
            ok = unsafe { EVP_CipherFinal_ex(ctx.0, rest, &raw mut fin) } != 0;
        }
        if !ok {
            return Err(if encrypt { fail() } else { bad_mac() });
        }
        out.truncate(done.saturating_add(usize::try_from(fin).unwrap_or(0)));
        if encrypt {
            // SAFETY: as above; the tag's room.
            if unsafe {
                EVP_CIPHER_CTX_ctrl(ctx.0, EVP_CTRL_AEAD_GET_TAG, tlen, tag.as_mut_ptr().cast())
            } <= 0
            {
                return Err(fail());
            }
            out.extend_from_slice(&tag);
        }
        *data = out;
        Ok(())
    }
}

/// A record that doesn't authenticate (`SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC`).
fn bad_mac() -> Error {
    Error::alert(
        rustyssl_abi::SSL_AD_BAD_RECORD_MAC,
        rustyssl_abi::SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC,
    )
}

// SAFETY: the cipher and key are owned and used by one record layer at a time.
unsafe impl Send for EvpAead {}

impl Aead for EvpAead {
    fn seal(&mut self, nonce: &[u8], aad: &[u8], data: &mut Vec<u8>) -> Result<()> {
        self.run(nonce, aad, data, true)
    }

    fn open(&mut self, nonce: &[u8], aad: &[u8], data: &mut Vec<u8>) -> Result<()> {
        self.run(nonce, aad, data, false)
    }
}

/// A CBC cipher (or no encryption): one stream, continued while each call's IV is the chain's
/// last ciphertext block (as the record layer gives it), and keyed again with the IV
/// otherwise. A provider may ignore a new init and keep its chain (PKCS#11's does), so the
/// record layer keeps to one stream, as OpenSSL's does.
struct EvpCipher {
    ctx: Option<CipherCtx>,
    encrypt: bool,
    key: Secret,
    /// The last ciphertext block, once keyed.
    chain: Option<Vec<u8>>,
}

impl Cipher for EvpCipher {
    fn crypt(&mut self, iv: &[u8], data: &mut [u8]) -> Result<()> {
        let Some(ctx) = &self.ctx else { return Ok(()) };
        // A new stream unless this continues the last one.
        if self.chain.as_deref() != Some(iv)
            // SAFETY: the keyed context; the key; the IV.
            && unsafe {
                EVP_CipherInit_ex(
                    ctx.0,
                    ptr::null(),
                    ptr::null_mut(),
                    self.key.bytes().as_ptr(),
                    iv.as_ptr(),
                    c_int::from(self.encrypt),
                )
            } == 0
        {
            return Err(fail());
        }
        // The stream's last ciphertext block afterwards: the input's when decrypting.
        let last = |d: &[u8]| {
            d.get(d.len().saturating_sub(iv.len())..)
                .map(<[u8]>::to_vec)
        };
        if !self.encrypt {
            self.chain = last(data);
        }
        let mut out = vec![0u8; data.len().saturating_add(32)];
        let mut outl: c_int = 0;
        let len = int_len(data.len())?;
        // SAFETY: as above; room for the data and a block.
        if unsafe { EVP_CipherUpdate(ctx.0, out.as_mut_ptr(), &raw mut outl, data.as_ptr(), len) }
            == 0
        {
            // The stream's state is unknown: the next call keys it again.
            self.chain = None;
            return Err(fail());
        }
        let n = usize::try_from(outl).map_err(|_| fail())?;
        let got = out.get(..n).ok_or_else(fail)?;
        if got.len() != data.len() {
            self.chain = None;
            return Err(fail());
        }
        data.copy_from_slice(got);
        if self.encrypt {
            self.chain = last(data);
        }
        Ok(())
    }
}

/// A key share for a group (or explicit DH parameters).
struct EvpShare {
    env: Env,
    key: Pkey,
    public: Vec<u8>,
    is_kem: bool,
    /// Explicit DH parameters (TLS 1.2's DHE), to make the peer's key with.
    dh: Option<(Vec<u8>, Vec<u8>)>,
    /// The group, to make the peer's key with.
    group: Option<Group>,
}

// SAFETY: the key is owned and used by one connection at a time; the library context is
// shared, as OpenSSL's are.
unsafe impl Send for EvpShare {}

impl KeyShare for EvpShare {
    fn public(&self) -> &[u8] {
        &self.public
    }

    fn derive(self: Box<Self>, peer: &[u8]) -> Result<Secret> {
        let p = &self.env;
        if self.is_kem {
            return p.decapsulate(&self.key, peer);
        }
        let peer_key = match (&self.dh, &self.group) {
            (Some((pp, g)), _) => p.dh_key(pp, g, Some(peer))?,
            (None, Some(g)) => p.peer_key(g, peer)?,
            (None, None) => return Err(fail()),
        };
        p.derive(&self.key, &peer_key)
    }
}

/// A key's encoded public value.
fn encoded_public(k: &Pkey) -> Result<Vec<u8>> {
    let mut buf: *mut u8 = ptr::null_mut();
    // SAFETY: the key; the slot for the C buffer it allocates.
    let n = unsafe { EVP_PKEY_get1_encoded_public_key(k.0, &raw mut buf) };
    if n == 0 || buf.is_null() {
        return Err(fail());
    }
    // SAFETY: the `n` octets it wrote.
    let v = unsafe { core::slice::from_raw_parts(buf, n) }.to_vec();
    // SAFETY: the buffer it allocated with OPENSSL_malloc, freed once.
    unsafe { mem::release(buf.cast()) };
    Ok(v)
}

impl Provider for EvpProvider {
    fn hash(&self, alg: HashAlg) -> Result<Box<dyn Hash>> {
        let md = self.fetch_md(hash_name(alg))?;
        // SAFETY: no preconditions.
        let ctx = MdCtx(unsafe { EVP_MD_CTX_new() });
        if ctx.0.is_null() {
            return Err(fail());
        }
        // SAFETY: the context; the digest (the context takes its own reference).
        if unsafe { EVP_DigestInit_ex(ctx.0, md.0, ptr::null_mut()) } == 0 {
            return Err(fail());
        }
        Ok(Box::new(EvpHash(ctx)))
    }

    fn hmac(&self, alg: HashAlg, key: &[u8]) -> Result<Box<dyn Mac>> {
        let template = self.hmac_ctx(alg, key, None)?;
        // SAFETY: the context made above.
        let ctx = MacCtx(unsafe { EVP_MAC_CTX_dup(template.0) });
        if ctx.0.is_null() {
            return Err(fail());
        }
        Ok(Box::new(EvpMac { template, ctx }))
    }

    fn aead(&self, alg: AeadAlg, key: &[u8]) -> Result<Box<dyn Aead>> {
        if key.len() != alg.key_len() {
            return Err(fail());
        }
        // SAFETY: the library context; a NUL-terminated name; the property query.
        let c = unsafe { EVP_CIPHER_fetch(self.libctx(), aead_name(alg).as_ptr(), self.propq()) };
        if c.is_null() {
            return Err(fail());
        }
        Ok(Box::new(EvpAead {
            cipher: CipherPtr(c),
            alg,
            key: Secret::new(key.to_vec()),
        }))
    }

    fn cipher(&self, alg: CipherAlg, key: &[u8], encrypt: bool) -> Result<Box<dyn Cipher>> {
        let Some(name) = cipher_name(alg) else {
            return Ok(Box::new(EvpCipher {
                ctx: None,
                encrypt,
                key: Secret::new(Vec::new()),
                chain: None,
            }));
        };
        if key.len() != alg.key_len() {
            return Err(fail());
        }
        // SAFETY: the library context; a NUL-terminated name; the property query.
        let c = CipherPtr(unsafe { EVP_CIPHER_fetch(self.libctx(), name.as_ptr(), self.propq()) });
        if c.0.is_null() {
            return Err(fail());
        }
        // SAFETY: no preconditions.
        let ctx = CipherCtx(unsafe { EVP_CIPHER_CTX_new() });
        if ctx.0.is_null() {
            return Err(fail());
        }
        // SAFETY: the context; the cipher; the key; no IV yet.
        let ok = unsafe { EVP_CipherInit_ex(ctx.0, c.0, ptr::null_mut(), key.as_ptr(), ptr::null(), c_int::from(encrypt)) } != 0
            // SAFETY: as above.
            && unsafe { EVP_CIPHER_CTX_set_padding(ctx.0, 0) } != 0;
        if !ok {
            return Err(fail());
        }
        Ok(Box::new(EvpCipher {
            ctx: Some(ctx),
            encrypt,
            key: Secret::new(key.to_vec()),
            chain: None,
        }))
    }

    fn tls_cbc_mac(
        &self,
        alg: HashAlg,
        key: &[u8],
        header: &[u8; 13],
        data: &[u8],
        data_size: usize,
    ) -> Result<Vec<u8>> {
        if data_size > data.len() {
            return Err(fail());
        }
        let ctx = self.hmac_ctx(alg, key, Some(data.len()))?;
        // SAFETY: the context; the header's 13 octets.
        let ok = unsafe { EVP_MAC_update(ctx.0, header.as_ptr(), header.len()) } != 0
            // SAFETY: as above; the record, of which the MAC reads `data.len()` octets in
            // constant time and covers the first `data_size`.
            && unsafe { EVP_MAC_update(ctx.0, data.as_ptr(), data_size) } != 0;
        if !ok {
            return Err(fail());
        }
        let mut out = vec![0u8; 64];
        let mut n = 0usize;
        // SAFETY: as above; room for any HMAC.
        if unsafe { EVP_MAC_final(ctx.0, out.as_mut_ptr(), &raw mut n, out.len()) } == 0 {
            return Err(fail());
        }
        out.truncate(n);
        Ok(out)
    }

    fn groups(&self) -> Vec<GroupInfo> {
        self.group_list().into_iter().map(|g| g.info).collect()
    }

    fn sigalgs(&self) -> Vec<SigalgInfo> {
        self.provider_sigalgs()
    }

    fn digest_available(&self, nid: i32) -> bool {
        self.fetchable(Fetchable::Digest(nid))
    }

    fn keytype_available(&self, name: &str) -> bool {
        self.fetchable(Fetchable::Keytype(name.to_owned()))
    }

    fn key_share(&self, id: u16) -> Result<Box<dyn KeyShare>> {
        let g = self.group(id)?;
        let key = self.env.generate_group_key(&g)?;
        let public = encoded_public(&key)?;
        Ok(Box::new(EvpShare {
            env: self.env.clone(),
            key,
            public,
            is_kem: g.info.is_kem,
            dh: None,
            group: Some(g),
        }))
    }

    fn dh_share(&self, p: &[u8], g: &[u8]) -> Result<Box<dyn KeyShare>> {
        let params = self.env.dh_key(p, g, None)?;
        let key = self.env.generate_from(&params)?;
        let public = encoded_public(&key)?;
        Ok(Box::new(EvpShare {
            env: self.env.clone(),
            key,
            public,
            is_kem: false,
            dh: Some((p.to_vec(), g.to_vec())),
            group: None,
        }))
    }

    fn respond(&self, id: u16, peer: &[u8]) -> Result<(Vec<u8>, Secret)> {
        let g = self.group(id)?;
        let peer_key = self.env.peer_key(&g, peer)?;
        if g.info.is_kem {
            return self.env.encapsulate(&peer_key);
        }
        let own = self.env.generate_group_key(&g)?;
        let public = encoded_public(&own)?;
        let secret = self.env.derive(&own, &peer_key)?;
        Ok((public, secret))
    }

    fn random(&self, out: &mut [u8], private: bool) -> Result<()> {
        let r = if private {
            // SAFETY: the library context; the buffer.
            unsafe { RAND_priv_bytes_ex(self.libctx(), out.as_mut_ptr(), out.len(), 0) }
        } else {
            // SAFETY: as above.
            unsafe { RAND_bytes_ex(self.libctx(), out.as_mut_ptr(), out.len(), 0) }
        };
        if r > 0 { Ok(()) } else { Err(fail()) }
    }

    fn sign(&self, key: KeyId, scheme: u16, msg: &[u8]) -> Result<Vec<u8>> {
        let pkey = self.key(key)?;
        // SAFETY: a registered key, which the registry keeps alive.
        let ctx = unsafe { self.sig_ctx(pkey, scheme, true) }?;
        let mut len = 0usize;
        // SAFETY: the signing context; a length only; the message.
        if unsafe {
            EVP_DigestSign(
                ctx.0,
                ptr::null_mut(),
                &raw mut len,
                msg.as_ptr(),
                msg.len(),
            )
        } <= 0
        {
            return Err(fail());
        }
        let mut sig = vec![0u8; len];
        // SAFETY: as above; the room.
        if unsafe {
            EVP_DigestSign(
                ctx.0,
                sig.as_mut_ptr(),
                &raw mut len,
                msg.as_ptr(),
                msg.len(),
            )
        } <= 0
        {
            return Err(fail());
        }
        sig.truncate(len);
        Ok(sig)
    }

    fn peer_key(&self, der: &[u8], _spki: bool) -> Result<PeerKey> {
        let (_owner, pkey) = self.cert_key(der)?;
        let is = |name: &CStr| {
            // SAFETY: the key decoded above; a NUL-terminated name.
            (unsafe { EVP_PKEY_is_a(pkey, name.as_ptr()) }) != 0
        };
        let kind = if is(c"RSA") {
            KeyKind::Rsa
        } else if is(c"RSA-PSS") {
            KeyKind::RsaPss
        } else if is(c"DSA") {
            KeyKind::Dsa
        } else if is(c"EC") {
            KeyKind::Ec
        } else if is(c"ED25519") {
            KeyKind::Ed25519
        } else if is(c"ED448") {
            KeyKind::Ed448
        } else {
            // SAFETY: as above; the name is the key management's, static.
            let n = unsafe { crate::evp::pkey::EVP_PKEY_get0_type_name(pkey) };
            let name = if n.is_null() {
                String::new()
            } else {
                // SAFETY: a NUL-terminated name.
                unsafe { CStr::from_ptr(n) }.to_string_lossy().into_owned()
            };
            KeyKind::Other(name)
        };
        let mut curve_nid = rustyssl_abi::NID_undef;
        if kind == KeyKind::Ec {
            let mut name = [0 as c_char; 80];
            let mut len = 0usize;
            // SAFETY: as above; the room.
            if unsafe { EVP_PKEY_get_group_name(pkey, name.as_mut_ptr(), name.len(), &raw mut len) }
                != 0
            {
                // SAFETY: the name written, NUL-terminated.
                curve_nid = unsafe { OBJ_sn2nid(name.as_ptr()) };
                if curve_nid == rustyssl_abi::NID_undef {
                    // SAFETY: as above.
                    curve_nid = unsafe { OBJ_txt2nid(name.as_ptr()) };
                }
            }
        }
        // A provider's key may report no size; OpenSSL asks only RSA-PSS keys theirs, so asking
        // leaves no error (`EVP_R_UNKNOWN_MAX_SIZE`) behind.
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: as above.
        let size = usize::try_from(unsafe { EVP_PKEY_get_size(pkey) }).unwrap_or(0);
        // SAFETY: no preconditions.
        unsafe { ERR_pop_to_mark() };
        // SAFETY: as above.
        let security_bits = unsafe { EVP_PKEY_get_security_bits(pkey) };
        let key_usage = match &_owner {
            // SAFETY: the certificate decoded above.
            KeyOwner::Cert(x) => unsafe { crate::x509::purpose::X509_get_key_usage(x.0) },
            KeyOwner::Key(_) => u32::MAX,
        };
        Ok(PeerKey {
            kind,
            curve_nid,
            size,
            security_bits,
            key_usage,
        })
    }

    fn verify(&self, cert: &[u8], scheme: u16, msg: &[u8], sig: &[u8]) -> Result<bool> {
        let (_x, pkey) = self.cert_key(cert)?;
        // SAFETY: the certificate's key, which `_x` keeps alive.
        let ctx = unsafe { self.sig_ctx(pkey, scheme, false) }?;
        // SAFETY: the verifying context; the signature; the message.
        Ok(
            unsafe { EVP_DigestVerify(ctx.0, sig.as_ptr(), sig.len(), msg.as_ptr(), msg.len()) }
                == 1,
        )
    }

    fn rsa_encrypt(&self, cert: &[u8], pms: &[u8]) -> Result<Vec<u8>> {
        let (_x, pkey) = self.cert_key(cert)?;
        // SAFETY: the library context; the certificate's key; the property query.
        let ctx = PkeyCtx(unsafe { EVP_PKEY_CTX_new_from_pkey(self.libctx(), pkey, self.propq()) });
        if ctx.0.is_null() {
            return Err(fail());
        }
        let mut len = 0usize;
        // SAFETY: the context made above.
        let ok = unsafe { EVP_PKEY_encrypt_init(ctx.0) } > 0
            // SAFETY: as above.
            && unsafe { EVP_PKEY_CTX_set_rsa_padding(ctx.0, RSA_PKCS1_PADDING) } > 0
            // SAFETY: as above; a length only.
            && unsafe { EVP_PKEY_encrypt(ctx.0, ptr::null_mut(), &raw mut len, pms.as_ptr(), pms.len()) } > 0;
        if !ok {
            return Err(fail());
        }
        let mut out = vec![0u8; len];
        // SAFETY: as above; the room.
        if unsafe {
            EVP_PKEY_encrypt(
                ctx.0,
                out.as_mut_ptr(),
                &raw mut len,
                pms.as_ptr(),
                pms.len(),
            )
        } <= 0
        {
            return Err(fail());
        }
        out.truncate(len);
        Ok(out)
    }

    fn rsa_decrypt_pms(
        &self,
        key: KeyId,
        ciphertext: &[u8],
        client_version: u16,
    ) -> Result<Secret> {
        /// `SSL_MAX_MASTER_KEY_LENGTH`.
        const PMS_LEN: usize = 48;
        let pkey = self.key(key)?;
        // SAFETY: the library context; a registered key; the property query.
        let ctx = PkeyCtx(unsafe { EVP_PKEY_CTX_new_from_pkey(self.libctx(), pkey, self.propq()) });
        if ctx.0.is_null() {
            return Err(fail());
        }
        let mut version = c_uint::from(client_version);
        // SAFETY: a static key; the version, which outlives the call below.
        let params = [
            unsafe {
                OSSL_PARAM_construct_uint(
                    OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION.as_ptr(),
                    &raw mut version,
                )
            },
            // SAFETY: no preconditions.
            unsafe { OSSL_PARAM_construct_end() },
        ];
        // SAFETY: the context made above.
        let ok = unsafe { EVP_PKEY_decrypt_init(ctx.0) } > 0
            // SAFETY: as above.
            && unsafe { EVP_PKEY_CTX_set_rsa_padding(ctx.0, RSA_PKCS1_WITH_TLS_PADDING) } > 0
            // SAFETY: as above; the terminated parameters.
            && unsafe { EVP_PKEY_CTX_set_params(ctx.0, params.as_ptr()) } > 0;
        if !ok {
            return Err(fail());
        }
        let mut out = vec![0u8; PMS_LEN];
        let mut len = PMS_LEN;
        // The padding check and implicit rejection happen inside, in constant time: any failure
        // yields a random secret of the right length.
        // SAFETY: as above; the room; the ciphertext.
        let good = unsafe {
            EVP_PKEY_decrypt(
                ctx.0,
                out.as_mut_ptr(),
                &raw mut len,
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        } > 0;
        if !good || len != PMS_LEN {
            return Err(Error::alert(
                rustyssl_abi::SSL_AD_DECRYPT_ERROR,
                rustyssl_abi::SSL_R_DECRYPTION_FAILED,
            ));
        }
        Ok(Secret::new(out))
    }
}

#[cfg(test)]
mod tests;
