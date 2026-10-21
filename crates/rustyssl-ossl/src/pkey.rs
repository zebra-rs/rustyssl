//! Keys and the signing context.

use core::ffi::c_char;

use crate::abi::{EVP_PKEY, EVP_PKEY_CTX};
use crate::ffi;
use crate::provider::LibCtx;
use crate::util::{cstring, string_at};

crate::handle!(
    /// An owned `EVP_PKEY`.
    Pkey, EVP_PKEY, EVP_PKEY_free
);

impl Pkey {
    /// Takes ownership of a key the caller got from the library.
    pub fn from_raw(p: *mut EVP_PKEY) -> Option<Self> {
        Self::from_ptr(p)
    }

    /// `EVP_PKEY_is_a`.
    pub fn is_a(&self, name: &str) -> bool {
        let Some(n) = cstring(name) else {
            return false;
        };
        // SAFETY: the key is live; n is a valid C string.
        unsafe { ffi::EVP_PKEY_is_a(self.as_ptr(), n.as_ptr()) == 1 }
    }

    /// `EVP_PKEY_get_default_digest_name`: what it returns, and the name.
    pub fn default_digest_name(&self) -> (i32, String) {
        let mut buf = [0 as c_char; 80];
        // SAFETY: the key is live; buf is writable for its length.
        let r = unsafe {
            ffi::EVP_PKEY_get_default_digest_name(self.as_ptr(), buf.as_mut_ptr(), buf.len())
        };
        let name = if r > 0 {
            string_at(buf.as_ptr()).unwrap_or_default()
        } else {
            String::new()
        };
        (r, name)
    }
}

crate::handle!(
    /// An owned `EVP_MD_CTX`.
    MdCtx, EVP_MD_CTX, EVP_MD_CTX_free
);

impl MdCtx {
    /// `EVP_MD_CTX_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::EVP_MD_CTX_new() })
    }

    /// `EVP_DigestSignInit_ex(ctx, &pctx, md, libctx, propq, pkey, NULL)`: whether it
    /// succeeded, and the key context it set up (owned by `self`).
    pub fn digest_sign_init(
        &self,
        md: Option<&str>,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
        pkey: &Pkey,
    ) -> (bool, PkeyCtxRef<'_>) {
        let md = md.map(cstring);
        let propq = propq.map(cstring);
        if md.as_ref().is_some_and(Option::is_none) || propq.as_ref().is_some_and(Option::is_none) {
            return (
                false,
                PkeyCtxRef(core::ptr::null_mut(), core::marker::PhantomData),
            );
        }
        let mdp = md
            .as_ref()
            .and_then(|m| m.as_ref())
            .map_or(core::ptr::null(), |m| m.as_ptr());
        let pqp = propq
            .as_ref()
            .and_then(|p| p.as_ref())
            .map_or(core::ptr::null(), |p| p.as_ptr());
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        let mut pctx: *mut EVP_PKEY_CTX = core::ptr::null_mut();
        // SAFETY: every pointer is live or NULL where the API allows it; pctx is a valid
        // out-pointer, and what it receives belongs to self.
        let r = unsafe {
            ffi::EVP_DigestSignInit_ex(
                self.as_ptr(),
                &mut pctx,
                mdp,
                ctx,
                pqp,
                pkey.as_ptr(),
                core::ptr::null(),
            )
        };
        (r == 1, PkeyCtxRef(pctx, core::marker::PhantomData))
    }
}

/// An `EVP_PKEY_CTX` borrowed from its owner (an `EVP_MD_CTX`'s, ...); it may be NULL.
#[derive(Clone, Copy)]
pub struct PkeyCtxRef<'a>(*mut EVP_PKEY_CTX, core::marker::PhantomData<&'a ()>);

impl PkeyCtxRef<'_> {
    /// `EVP_PKEY_CTX_ctrl_str(ctx, type, value)`: what it returns (-1 for NULL, as the
    /// library does for a context it can't use).
    pub fn ctrl_str(self, kind: &str, value: &str) -> i32 {
        let (Some(k), Some(v)) = (cstring(kind), cstring(value)) else {
            return -1;
        };
        if self.0.is_null() {
            return -1;
        }
        // SAFETY: the context is live (borrowed from its owner); the strings are valid.
        unsafe { ffi::EVP_PKEY_CTX_ctrl_str(self.0, k.as_ptr(), v.as_ptr()) }
    }
}

crate::handle!(
    /// An owned `EVP_PKEY_CTX`.
    PkeyCtx, EVP_PKEY_CTX, EVP_PKEY_CTX_free
);

/// A C `int` for a length the C API takes as one; `None` if it doesn't fit.
fn c_len(n: usize) -> Option<core::ffi::c_int> {
    core::ffi::c_int::try_from(n).ok()
}

impl Pkey {
    /// `EVP_PKEY_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::EVP_PKEY_new() })
    }

    /// `d2i_PrivateKey(type, NULL, &p, len)`.
    pub fn private_from_der(kind: core::ffi::c_int, der: &[u8]) -> Option<Self> {
        let len = core::ffi::c_long::try_from(der.len()).ok()?;
        let mut p = der.as_ptr();
        // SAFETY: p points to len bytes; the call only reads them and advances p.
        Self::from_ptr(unsafe { ffi::d2i_PrivateKey(kind, core::ptr::null_mut(), &mut p, len) })
    }

    /// `EVP_PKEY_get_size`.
    pub fn size(&self) -> core::ffi::c_int {
        // SAFETY: the key is live.
        unsafe { ffi::EVP_PKEY_get_size(self.as_ptr()) }
    }

    /// `get_dsa` of upstream's `testdsa.h`: a key pair of `kind` ("DSA") from its FFC
    /// parameters and keys, big-endian (`OSSL_PARAM_BLD` with BIGNUMs, `EVP_PKEY_fromdata`).
    pub fn ffc_keypair(
        kind: &str,
        p: &[u8],
        q: &[u8],
        g: &[u8],
        private: &[u8],
        public: &[u8],
    ) -> Option<Self> {
        use crate::abi::{
            EVP_PKEY_KEYPAIR, OSSL_PKEY_PARAM_FFC_G, OSSL_PKEY_PARAM_FFC_P, OSSL_PKEY_PARAM_FFC_Q,
            OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY,
        };
        let pctx = PkeyCtx::new_from_name(None, kind, None)?;
        let parts = [
            (OSSL_PKEY_PARAM_FFC_P, p),
            (OSSL_PKEY_PARAM_FFC_Q, q),
            (OSSL_PKEY_PARAM_FFC_G, g),
            (OSSL_PKEY_PARAM_PRIV_KEY, private),
            (OSSL_PKEY_PARAM_PUB_KEY, public),
        ];
        let mut bns = Vec::new();
        for (_, bytes) in &parts {
            let n = c_len(bytes.len())?;
            // SAFETY: bytes holds n bytes; a NULL BIGNUM asks for a new one, freed below.
            let bn = unsafe { ffi::BN_bin2bn(bytes.as_ptr(), n, core::ptr::null_mut()) };
            if bn.is_null() {
                break;
            }
            bns.push(bn);
        }
        let mut key = None;
        if bns.len() == parts.len() {
            // SAFETY: no arguments.
            let bld = unsafe { ffi::OSSL_PARAM_BLD_new() };
            if !bld.is_null() {
                let pushed = parts.iter().zip(&bns).all(|((name, _), &bn)| {
                    // SAFETY: bld and bn are live; the name is a static C string.
                    unsafe { ffi::OSSL_PARAM_BLD_push_BN(bld, name.as_ptr(), bn) == 1 }
                });
                let params = if pushed {
                    // SAFETY: bld is live; the list is the caller's, freed below.
                    unsafe { ffi::OSSL_PARAM_BLD_to_param(bld) }
                } else {
                    core::ptr::null_mut()
                };
                if !params.is_null() {
                    let mut pkey: *mut EVP_PKEY = core::ptr::null_mut();
                    let ok = pctx.fromdata_init() > 0
                        // SAFETY: the context is live; params is a live list; pkey is an
                        // out-pointer whose key becomes ours.
                        && unsafe {
                            ffi::EVP_PKEY_fromdata(pctx.as_ptr(), &mut pkey, EVP_PKEY_KEYPAIR, params)
                        } > 0;
                    key = if ok { Pkey::from_ptr(pkey) } else { None };
                    // SAFETY: the list from OSSL_PARAM_BLD_to_param, freed once.
                    unsafe { ffi::OSSL_PARAM_free(params) };
                }
                // SAFETY: the builder is ours, freed once.
                unsafe { ffi::OSSL_PARAM_BLD_free(bld) };
            }
        }
        for bn in bns {
            // SAFETY: each BIGNUM is ours (the builder copied it), freed once.
            unsafe { ffi::BN_free(bn) };
        }
        key
    }
}

/// `get_legacy_pkey_id(libctx, algname, NULL)` of `apps/lib/engine.c`: the NID of an
/// engine's key method named `algname`, `NID_undef` if no engine has one.
pub fn legacy_pkey_id(algname: &str) -> core::ffi::c_int {
    let Some(name) = cstring(algname) else {
        return crate::abi::NID_undef;
    };
    crate::err::set_mark();
    let mut tmpeng: *mut crate::abi::ENGINE = core::ptr::null_mut();
    // SAFETY: tmpeng is a valid out-pointer; name is a valid C string (-1: its length).
    let ameth = unsafe { ffi::EVP_PKEY_asn1_find_str(&mut tmpeng, name.as_ptr(), -1) };
    // SAFETY: tmpeng is NULL or a functional reference the lookup took.
    unsafe { ffi::ENGINE_finish(tmpeng) };
    crate::err::pop_to_mark();
    // Only a method from an engine counts.
    if ameth.is_null() || tmpeng.is_null() {
        return crate::abi::NID_undef;
    }
    let mut id = crate::abi::NID_undef;
    // SAFETY: ameth is a live method; the other outputs are NULL (not wanted).
    unsafe {
        ffi::EVP_PKEY_asn1_get0_info(
            &mut id,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            ameth,
        )
    };
    id
}

fn opt_cstring(s: Option<&str>) -> Option<Option<std::ffi::CString>> {
    match s {
        Some(s) => cstring(s).map(Some),
        None => Some(None),
    }
}

impl PkeyCtx {
    /// `EVP_PKEY_CTX_new(pkey, NULL)`.
    pub fn new(pkey: &Pkey) -> Option<Self> {
        // SAFETY: the key is live; the context takes its own reference.
        Self::from_ptr(unsafe { ffi::EVP_PKEY_CTX_new(pkey.as_ptr(), core::ptr::null_mut()) })
    }

    /// `EVP_PKEY_CTX_new_id(id, NULL)`.
    pub fn new_id(id: core::ffi::c_int) -> Option<Self> {
        // SAFETY: any id is accepted (unknown ones fail).
        Self::from_ptr(unsafe { ffi::EVP_PKEY_CTX_new_id(id, core::ptr::null_mut()) })
    }

    /// `EVP_PKEY_CTX_new_from_name(libctx, name, propq)`.
    pub fn new_from_name(libctx: Option<&LibCtx>, name: &str, propq: Option<&str>) -> Option<Self> {
        let n = cstring(name)?;
        let pq = opt_cstring(propq)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: ctx is NULL or live; the strings are valid or NULL.
        Self::from_ptr(unsafe {
            ffi::EVP_PKEY_CTX_new_from_name(
                ctx,
                n.as_ptr(),
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            )
        })
    }

    /// `EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq)`.
    pub fn new_from_pkey(
        libctx: Option<&LibCtx>,
        pkey: &Pkey,
        propq: Option<&str>,
    ) -> Option<Self> {
        let pq = opt_cstring(propq)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: ctx is NULL or live; the key is live; propq is valid or NULL.
        Self::from_ptr(unsafe {
            ffi::EVP_PKEY_CTX_new_from_pkey(
                ctx,
                pkey.as_ptr(),
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            )
        })
    }

    /// Calls `f` on the context: for the `EVP_PKEY_*_init` and `EVP_PKEY_CTX_set_*` calls
    /// that take nothing else but integers.
    fn call(&self, f: unsafe fn(*mut EVP_PKEY_CTX) -> core::ffi::c_int) -> core::ffi::c_int {
        // SAFETY: the context is live; f is one of the library's functions on a context.
        unsafe { f(self.as_ptr()) }
    }

    /// `EVP_PKEY_sign_init`.
    pub fn sign_init(&self) -> core::ffi::c_int {
        self.call(ffi::EVP_PKEY_sign_init)
    }

    /// `EVP_PKEY_verify_init`.
    pub fn verify_init(&self) -> core::ffi::c_int {
        self.call(ffi::EVP_PKEY_verify_init)
    }

    /// `EVP_PKEY_encrypt_init`.
    pub fn encrypt_init(&self) -> core::ffi::c_int {
        self.call(ffi::EVP_PKEY_encrypt_init)
    }

    /// `EVP_PKEY_decrypt_init`.
    pub fn decrypt_init(&self) -> core::ffi::c_int {
        self.call(ffi::EVP_PKEY_decrypt_init)
    }

    /// `EVP_PKEY_derive_init`.
    pub fn derive_init(&self) -> core::ffi::c_int {
        self.call(ffi::EVP_PKEY_derive_init)
    }

    /// `EVP_PKEY_keygen_init`.
    pub fn keygen_init(&self) -> core::ffi::c_int {
        self.call(ffi::EVP_PKEY_keygen_init)
    }

    /// `EVP_PKEY_paramgen_init`.
    pub fn paramgen_init(&self) -> core::ffi::c_int {
        self.call(ffi::EVP_PKEY_paramgen_init)
    }

    /// `EVP_PKEY_fromdata_init`.
    pub fn fromdata_init(&self) -> core::ffi::c_int {
        self.call(ffi::EVP_PKEY_fromdata_init)
    }

    /// `EVP_PKEY_encapsulate_init(ctx, NULL)`.
    pub fn encapsulate_init(&self) -> core::ffi::c_int {
        // SAFETY: the context is live; no parameters.
        unsafe { ffi::EVP_PKEY_encapsulate_init(self.as_ptr(), core::ptr::null()) }
    }

    /// `EVP_PKEY_decapsulate_init(ctx, NULL)`.
    pub fn decapsulate_init(&self) -> core::ffi::c_int {
        // SAFETY: the context is live; no parameters.
        unsafe { ffi::EVP_PKEY_decapsulate_init(self.as_ptr(), core::ptr::null()) }
    }

    /// `EVP_PKEY_sign_message_init(ctx, alg, NULL)`.
    pub fn sign_message_init(&self, alg: &crate::evp::Signature) -> core::ffi::c_int {
        // SAFETY: the context and algorithm are live; no parameters.
        unsafe { ffi::EVP_PKEY_sign_message_init(self.as_ptr(), alg.as_ptr(), core::ptr::null()) }
    }

    /// `EVP_PKEY_verify_message_init(ctx, alg, NULL)`.
    pub fn verify_message_init(&self, alg: &crate::evp::Signature) -> core::ffi::c_int {
        // SAFETY: as above.
        unsafe { ffi::EVP_PKEY_verify_message_init(self.as_ptr(), alg.as_ptr(), core::ptr::null()) }
    }

    /// `EVP_PKEY_sign(ctx, sig, &siglen, tbs, tbslen)` with `siglen = sig.len()`: what it
    /// returns, and the length.
    pub fn sign(&self, sig: &mut [u8], tbs: &[u8]) -> (core::ffi::c_int, usize) {
        let mut len = sig.len();
        // SAFETY: the context is live; sig is writable for len bytes, tbs readable for its.
        let r = unsafe {
            ffi::EVP_PKEY_sign(
                self.as_ptr(),
                sig.as_mut_ptr(),
                &mut len,
                tbs.as_ptr(),
                tbs.len(),
            )
        };
        (r, len)
    }

    /// `EVP_PKEY_sign(ctx, NULL, &siglen, tbs, tbslen)`: the signature's maximum length.
    pub fn sign_length(&self, tbs: &[u8]) -> (core::ffi::c_int, usize) {
        let mut len = 0;
        // SAFETY: the context is live; a NULL signature asks for the length.
        let r = unsafe {
            ffi::EVP_PKEY_sign(
                self.as_ptr(),
                core::ptr::null_mut(),
                &mut len,
                tbs.as_ptr(),
                tbs.len(),
            )
        };
        (r, len)
    }

    /// `EVP_PKEY_verify(ctx, sig, siglen, tbs, tbslen)`.
    pub fn verify(&self, sig: &[u8], tbs: &[u8]) -> core::ffi::c_int {
        // SAFETY: the context is live; both buffers are readable for their lengths.
        unsafe {
            ffi::EVP_PKEY_verify(
                self.as_ptr(),
                sig.as_ptr(),
                sig.len(),
                tbs.as_ptr(),
                tbs.len(),
            )
        }
    }

    /// `EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen)` with `outlen = out.len()`.
    pub fn encrypt(&self, out: &mut [u8], input: &[u8]) -> (core::ffi::c_int, usize) {
        let mut len = out.len();
        // SAFETY: as in sign.
        let r = unsafe {
            ffi::EVP_PKEY_encrypt(
                self.as_ptr(),
                out.as_mut_ptr(),
                &mut len,
                input.as_ptr(),
                input.len(),
            )
        };
        (r, len)
    }

    /// `EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen)` with `outlen = out.len()`.
    pub fn decrypt(&self, out: &mut [u8], input: &[u8]) -> (core::ffi::c_int, usize) {
        let mut len = out.len();
        // SAFETY: as in sign.
        let r = unsafe {
            ffi::EVP_PKEY_decrypt(
                self.as_ptr(),
                out.as_mut_ptr(),
                &mut len,
                input.as_ptr(),
                input.len(),
            )
        };
        (r, len)
    }

    /// `EVP_PKEY_derive_set_peer(ctx, peer)`.
    pub fn derive_set_peer(&self, peer: &Pkey) -> core::ffi::c_int {
        // SAFETY: both are live; the context takes its own reference to the peer.
        unsafe { ffi::EVP_PKEY_derive_set_peer(self.as_ptr(), peer.as_ptr()) }
    }

    /// `EVP_PKEY_derive(ctx, out, &len)` with `len` as given (at most `out.len()`).
    pub fn derive(&self, out: &mut [u8], len: usize) -> (core::ffi::c_int, usize) {
        let mut l = len.min(out.len());
        // SAFETY: the context is live; out is writable for l bytes.
        let r = unsafe { ffi::EVP_PKEY_derive(self.as_ptr(), out.as_mut_ptr(), &mut l) };
        (r, l)
    }

    /// `EVP_PKEY_derive(ctx, NULL, &len)`: the secret's length.
    pub fn derive_length(&self) -> (core::ffi::c_int, usize) {
        let mut l = 0;
        // SAFETY: the context is live; NULL asks for the length.
        let r = unsafe { ffi::EVP_PKEY_derive(self.as_ptr(), core::ptr::null_mut(), &mut l) };
        (r, l)
    }

    /// `EVP_PKEY_keygen(ctx, &pkey)`, into `into` when given (as upstream passes a key it
    /// made with `EVP_PKEY_new`): what it returns, and the key.
    pub fn keygen(&self, into: Option<Pkey>) -> (core::ffi::c_int, Option<Pkey>) {
        let mut p = into.map_or(core::ptr::null_mut(), Pkey::into_ptr);
        // SAFETY: the context is live; p is NULL or a key owned here, which the call fills
        // (or replaces) and which stays ours.
        let r = unsafe { ffi::EVP_PKEY_keygen(self.as_ptr(), &mut p) };
        (r, Pkey::from_ptr(p))
    }

    /// `EVP_PKEY_paramgen(ctx, &pkey)`.
    pub fn paramgen(&self) -> (core::ffi::c_int, Option<Pkey>) {
        let mut p = core::ptr::null_mut();
        // SAFETY: as above.
        let r = unsafe { ffi::EVP_PKEY_paramgen(self.as_ptr(), &mut p) };
        (r, Pkey::from_ptr(p))
    }

    /// `EVP_PKEY_CTX_set_params(ctx, params)`.
    pub fn set_params(&self, params: &crate::params::Params) -> core::ffi::c_int {
        // SAFETY: the context is live; the list is END-terminated and live.
        unsafe { ffi::EVP_PKEY_CTX_set_params(self.as_ptr(), params.as_ptr()) }
    }

    /// `EVP_PKEY_CTX_set_ec_paramgen_curve_nid`.
    pub fn set_ec_paramgen_curve_nid(&self, nid: core::ffi::c_int) -> core::ffi::c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_CTX_set_ec_paramgen_curve_nid(self.as_ptr(), nid) }
    }

    /// `EVP_PKEY_CTX_set_dh_nid`.
    pub fn set_dh_nid(&self, nid: core::ffi::c_int) -> core::ffi::c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_CTX_set_dh_nid(self.as_ptr(), nid) }
    }

    /// `EVP_PKEY_CTX_set_dsa_paramgen_bits`.
    pub fn set_dsa_paramgen_bits(&self, bits: core::ffi::c_int) -> core::ffi::c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_CTX_set_dsa_paramgen_bits(self.as_ptr(), bits) }
    }

    /// `EVP_PKEY_CTX_set_rsa_keygen_bits`.
    pub fn set_rsa_keygen_bits(&self, bits: core::ffi::c_int) -> core::ffi::c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_CTX_set_rsa_keygen_bits(self.as_ptr(), bits) }
    }

    /// `EVP_PKEY_CTX_set_rsa_keygen_primes`.
    pub fn set_rsa_keygen_primes(&self, primes: core::ffi::c_int) -> core::ffi::c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_CTX_set_rsa_keygen_primes(self.as_ptr(), primes) }
    }

    /// `EVP_PKEY_CTX_set1_rsa_keygen_pubexp` with a BIGNUM of `e` (`BN_set_word`): `None`
    /// when the BIGNUM can't be made.
    pub fn set1_rsa_keygen_pubexp(&self, e: core::ffi::c_ulong) -> Option<core::ffi::c_int> {
        // SAFETY: no arguments.
        let bn = unsafe { ffi::BN_new() };
        if bn.is_null() {
            return None;
        }
        // SAFETY: bn is live.
        let r = if unsafe { ffi::BN_set_word(bn, e) } == 1 {
            // SAFETY: the context and bn are live; the context copies bn.
            Some(unsafe { ffi::EVP_PKEY_CTX_set1_rsa_keygen_pubexp(self.as_ptr(), bn) })
        } else {
            None
        };
        // SAFETY: bn is ours, freed once.
        unsafe { ffi::BN_free(bn) };
        r
    }

    /// `EVP_PKEY_CTX_set_rsa_padding`.
    pub fn set_rsa_padding(&self, pad: core::ffi::c_int) -> core::ffi::c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_CTX_set_rsa_padding(self.as_ptr(), pad) }
    }

    /// `EVP_PKEY_CTX_set_kem_op(ctx, op)`.
    pub fn set_kem_op(&self, op: &str) -> core::ffi::c_int {
        let Some(o) = cstring(op) else {
            return 0;
        };
        // SAFETY: the context is live; o is a valid C string.
        unsafe { ffi::EVP_PKEY_CTX_set_kem_op(self.as_ptr(), o.as_ptr()) }
    }

    /// `EVP_PKEY_CTX_set1_id(ctx, id, len)`.
    pub fn set1_id(&self, id: &[u8]) -> core::ffi::c_int {
        let Some(n) = c_len(id.len()) else {
            return 0;
        };
        // SAFETY: the context is live; id is readable for n bytes (copied).
        unsafe { ffi::EVP_PKEY_CTX_set1_id(self.as_ptr(), id.as_ptr().cast(), n) }
    }

    /// `EVP_PKEY_encapsulate(ctx, NULL, &outlen, NULL, &secretlen)`: the lengths.
    pub fn encapsulate_lengths(&self) -> (core::ffi::c_int, usize, usize) {
        let (mut o, mut s) = (0, 0);
        // SAFETY: the context is live; NULL buffers ask for the lengths.
        let r = unsafe {
            ffi::EVP_PKEY_encapsulate(
                self.as_ptr(),
                core::ptr::null_mut(),
                &mut o,
                core::ptr::null_mut(),
                &mut s,
            )
        };
        (r, o, s)
    }

    /// `EVP_PKEY_encapsulate(ctx, out, &outlen, secret, &secretlen)`, the lengths those of
    /// the buffers: what it returns, and the lengths written.
    pub fn encapsulate(
        &self,
        out: &mut [u8],
        secret: &mut [u8],
    ) -> (core::ffi::c_int, usize, usize) {
        let (mut o, mut s) = (out.len(), secret.len());
        // SAFETY: the context is live; the buffers are writable for their lengths.
        let r = unsafe {
            ffi::EVP_PKEY_encapsulate(
                self.as_ptr(),
                out.as_mut_ptr(),
                &mut o,
                secret.as_mut_ptr(),
                &mut s,
            )
        };
        (r, o, s)
    }

    /// `EVP_PKEY_decapsulate(ctx, NULL, &secretlen, in, inlen)`: the length.
    pub fn decapsulate_length(&self, input: &[u8]) -> (core::ffi::c_int, usize) {
        let mut s = 0;
        // SAFETY: the context is live; NULL asks for the length; input is readable.
        let r = unsafe {
            ffi::EVP_PKEY_decapsulate(
                self.as_ptr(),
                core::ptr::null_mut(),
                &mut s,
                input.as_ptr(),
                input.len(),
            )
        };
        (r, s)
    }

    /// `EVP_PKEY_decapsulate(ctx, secret, &secretlen, in, inlen)` with `secretlen` the
    /// buffer's length.
    pub fn decapsulate(&self, secret: &mut [u8], input: &[u8]) -> (core::ffi::c_int, usize) {
        let mut s = secret.len();
        // SAFETY: the context is live; the buffers are valid for their lengths.
        let r = unsafe {
            ffi::EVP_PKEY_decapsulate(
                self.as_ptr(),
                secret.as_mut_ptr(),
                &mut s,
                input.as_ptr(),
                input.len(),
            )
        };
        (r, s)
    }
}

impl MdCtx {
    /// `EVP_DigestInit(ctx, md)`.
    pub fn digest_init(&self, md: &crate::evp::Md) -> core::ffi::c_int {
        // SAFETY: both are live.
        unsafe { ffi::EVP_DigestInit(self.as_ptr(), md.as_ptr()) }
    }

    /// `EVP_DigestInit_ex2(ctx, md, NULL)`.
    pub fn digest_init_ex2(&self, md: &crate::evp::Md) -> bool {
        // SAFETY: both are live; no parameters.
        unsafe { ffi::EVP_DigestInit_ex2(self.as_ptr(), md.as_ptr(), core::ptr::null()) == 1 }
    }

    /// `EVP_DigestUpdate(ctx, data, len)`.
    pub fn digest_update(&self, data: &[u8]) -> bool {
        // SAFETY: the context is live; data is readable for its length.
        unsafe { ffi::EVP_DigestUpdate(self.as_ptr(), data.as_ptr().cast(), data.len()) == 1 }
    }

    /// `EVP_DigestFinalXOF(ctx, out, out.len())`.
    pub fn digest_final_xof(&self, out: &mut [u8]) -> bool {
        // SAFETY: the context is live; out is writable for its length.
        unsafe { ffi::EVP_DigestFinalXOF(self.as_ptr(), out.as_mut_ptr(), out.len()) == 1 }
    }

    /// `EVP_DigestSignInit(ctx, NULL, md, NULL, pkey)`, `md` NULL or `EVP_sm3()`.
    pub fn sign_init(&self, sm3: bool, pkey: &Pkey) -> core::ffi::c_int {
        let md = if sm3 {
            // SAFETY: no arguments; a static digest.
            unsafe { ffi::EVP_sm3() }
        } else {
            core::ptr::null()
        };
        // SAFETY: the context and key are live; the key context made stays the context's.
        unsafe {
            ffi::EVP_DigestSignInit(
                self.as_ptr(),
                core::ptr::null_mut(),
                md,
                core::ptr::null_mut(),
                pkey.as_ptr(),
            )
        }
    }

    /// `EVP_DigestSignInit(ctx, NULL, NULL, NULL, NULL)`: again, with the key it has.
    pub fn sign_reinit(&self) -> core::ffi::c_int {
        // SAFETY: the context is live; NULLs keep what it has.
        unsafe {
            ffi::EVP_DigestSignInit(
                self.as_ptr(),
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        }
    }

    /// `EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey)`, `md` NULL or `EVP_sm3()`.
    pub fn verify_init(&self, sm3: bool, pkey: &Pkey) -> core::ffi::c_int {
        let md = if sm3 {
            // SAFETY: as in sign_init.
            unsafe { ffi::EVP_sm3() }
        } else {
            core::ptr::null()
        };
        // SAFETY: as in sign_init.
        unsafe {
            ffi::EVP_DigestVerifyInit(
                self.as_ptr(),
                core::ptr::null_mut(),
                md,
                core::ptr::null_mut(),
                pkey.as_ptr(),
            )
        }
    }

    /// `EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, NULL)`.
    pub fn verify_reinit(&self) -> core::ffi::c_int {
        // SAFETY: as in sign_reinit.
        unsafe {
            ffi::EVP_DigestVerifyInit(
                self.as_ptr(),
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        }
    }

    /// `EVP_DigestSign(ctx, sig, &siglen, tbs, tbslen)` with `siglen` as given (at most
    /// `sig.len()`).
    pub fn sign(&self, sig: &mut [u8], siglen: usize, tbs: &[u8]) -> (core::ffi::c_int, usize) {
        let mut l = siglen.min(sig.len());
        // SAFETY: the context is live; sig is writable for l bytes; tbs readable.
        let r = unsafe {
            ffi::EVP_DigestSign(
                self.as_ptr(),
                sig.as_mut_ptr(),
                &mut l,
                tbs.as_ptr(),
                tbs.len(),
            )
        };
        (r, l)
    }

    /// `EVP_DigestVerify(ctx, sig, siglen, tbs, tbslen)`.
    pub fn verify(&self, sig: &[u8], tbs: &[u8]) -> core::ffi::c_int {
        // SAFETY: the context is live; both buffers are readable for their lengths.
        unsafe {
            ffi::EVP_DigestVerify(
                self.as_ptr(),
                sig.as_ptr(),
                sig.len(),
                tbs.as_ptr(),
                tbs.len(),
            )
        }
    }

    /// `EVP_MD_CTX_set_pkey_ctx(ctx, pctx)`: the context uses `pctx`, which it doesn't own;
    /// `pctx` must outlive its use here.
    pub fn set_pkey_ctx(&self, pctx: &PkeyCtx) {
        // SAFETY: both are live; the MD context keeps the pointer without owning it, and its
        // owner (the caller) keeps it alive as long as this context uses it.
        unsafe { ffi::EVP_MD_CTX_set_pkey_ctx(self.as_ptr(), pctx.as_ptr()) };
    }
}
