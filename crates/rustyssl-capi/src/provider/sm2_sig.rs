//! The default provider's SM2 signatures (`sm2_sig.c`): signing and verifying a digest-sized
//! number as it is, and digest-signing and digest-verifying a message with SM3, whose digest
//! starts with the key's Z value over the distinguishing ID (`distid`, empty unless set).
//!
//! The context follows OpenSSL's: the digest is SM3 (another named is refused), the ID can be
//! set only before the Z value is computed (on the first update or final), and the algorithm
//! identifier is SM2-with-SM3, made by a digest init.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    EC_KEY, ERR_LIB_PROV, EVP_MD_CTX, NID_SM2_with_SM3, NID_sm3, OSSL_DIGEST_NAME_SM3,
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
    OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
    OSSL_FUNC_SIGNATURE_DUPCTX, OSSL_FUNC_SIGNATURE_FREECTX, OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
    OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
    OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, OSSL_FUNC_SIGNATURE_NEWCTX,
    OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_SIGN, OSSL_FUNC_SIGNATURE_SIGN_INIT, OSSL_FUNC_SIGNATURE_VERIFY,
    OSSL_FUNC_SIGNATURE_VERIFY_INIT, OSSL_LIB_CTX, OSSL_PARAM, OSSL_PARAM_OCTET_STRING,
    OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_STRING, OSSL_PKEY_PARAM_DIST_ID,
    OSSL_SIGNATURE_PARAM_ALGORITHM_ID, OSSL_SIGNATURE_PARAM_DIGEST,
    OSSL_SIGNATURE_PARAM_DIGEST_SIZE, PROV_R_INVALID_DIGEST, PROV_R_NO_KEY_SET,
    PROV_R_XOF_DIGESTS_NOT_ALLOWED,
};
use rustyssl_asn1::objects;

use super::builtin::libctx_of;
use super::macs::{SIZE_T, boxed, context, is_empty, locate, unbox};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::ec::ecdsa::ECDSA_size;
use crate::ec::key::{EC_KEY_free, EC_KEY_up_ref};
use crate::ec::sm2::{compute_z_digest, internal_sign, internal_verify};
use crate::err;
use crate::evp::digest::{EVP_MD_get_size, EVP_MD_get_type, EVP_MD_get0_name, EVP_MD_is_a};
use crate::evp::md_ctx::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex2, EVP_DigestUpdate, EVP_MD_CTX_copy_ex, EVP_MD_CTX_free,
    EVP_MD_CTX_get_params, EVP_MD_CTX_new, EVP_MD_CTX_set_params, EVP_MD_gettable_ctx_params,
    EVP_MD_settable_ctx_params, EVP_MD_xof,
};
use crate::ffi::{bytes, ffi_callback};
use crate::mem;
use crate::params::{
    OSSL_PARAM_get_octet_string, OSSL_PARAM_get_size_t, OSSL_PARAM_get_utf8_string,
    OSSL_PARAM_locate, OSSL_PARAM_set_octet_string, OSSL_PARAM_set_size_t,
    OSSL_PARAM_set_utf8_string,
};
use crate::rsa::Md;

/// `OSSL_MAX_NAME_SIZE`.
const MAX_NAME: usize = 50;

/// `SM3_DIGEST_LENGTH`.
const SM3_DIGEST_LENGTH: usize = 32;

/// `PROV_SM2_CTX`.
struct Sm2Ctx {
    libctx: *mut OSSL_LIB_CTX,
    propq: Option<CString>,
    /// The key, with a reference this holds.
    ec: *mut EC_KEY,
    /// Whether the Z value is still to be fed to the digest.
    flag_compute_z_digest: bool,
    mdname: Vec<u8>,
    aid: Vec<u8>,
    md: Option<Md>,
    mdctx: *mut EVP_MD_CTX,
    mdsize: usize,
    /// The distinguishing ID (none and empty alike are an empty Z prefix).
    id: Option<Vec<u8>>,
}

impl Drop for Sm2Ctx {
    fn drop(&mut self) {
        // SAFETY: the context this holds, or NULL.
        unsafe { EVP_MD_CTX_free(self.mdctx) };
        // SAFETY: the reference this holds, or NULL.
        unsafe { EC_KEY_free(self.ec) };
    }
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `sm2sig_newctx`.
unsafe fn ctx<'a>(vctx: *mut c_void) -> Option<&'a mut Sm2Ctx> {
    // SAFETY: the caller's guarantee.
    unsafe { context::<Sm2Ctx>(vctx) }
}

/// A DER element (the identifier is short).
fn der(tag: u8, content: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![tag, u8::try_from(content.len()).ok().filter(|&l| l < 0x80)?];
    out.extend_from_slice(content);
    Some(out)
}

impl Sm2Ctx {
    /// `sm2sig_set_mdname`: SM3 (fetched once, by the context's name), and `mdname` only if
    /// it names that digest.
    fn set_mdname(&mut self, mdname: Option<&CStr>) -> bool {
        const F: &str = "sm2sig_set_mdname";
        if self.md.is_none() {
            let name = CString::new(self.mdname.clone()).unwrap_or_default();
            let props = self.propq.as_deref().map_or(ptr::null(), CStr::as_ptr);
            // SAFETY: the context's library context; a name and a query.
            self.md = unsafe { Md::fetch(self.libctx, &name, props) };
        }
        let Some(md) = self.md.as_ref() else {
            return false;
        };
        // SAFETY: the digest.
        if unsafe { EVP_MD_xof(md.ptr()) } != 0 {
            err::raise(ERR_LIB_PROV, PROV_R_XOF_DIGESTS_NOT_ALLOWED, F);
            return false;
        }
        let Some(name) = mdname else { return true };
        // SAFETY: the digest; a string.
        if name.to_bytes().len() >= MAX_NAME || unsafe { EVP_MD_is_a(md.ptr(), name.as_ptr()) } == 0
        {
            err::raise_with_text(
                ERR_LIB_PROV,
                PROV_R_INVALID_DIGEST,
                F,
                &format!("digest={}", String::from_utf8_lossy(name.to_bytes())),
            );
            return false;
        }
        self.mdname = name.to_bytes().to_vec();
        true
    }

    /// `sm2sig_compute_z_digest`: the Z value fed to the digest, once.
    fn compute_z(&mut self) -> bool {
        if !self.flag_compute_z_digest {
            return true;
        }
        self.flag_compute_z_digest = false;
        let mut z = vec![0u8; self.mdsize];
        let md = self
            .md
            .as_ref()
            .map_or(ptr::null(), |m| m.ptr().cast_const());
        let id = self.id.as_deref().unwrap_or_default();
        // SAFETY: room for the digest (SM3's size, the only one); the digest; the key.
        let z_ok = unsafe { compute_z_digest(z.as_mut_ptr(), md, id, self.ec) };
        // SAFETY: the context's digest context; the Z value.
        z_ok && unsafe { EVP_DigestUpdate(self.mdctx, z.as_ptr().cast(), z.len()) } != 0
    }
}

ffi_callback! {
    /// `sm2sig_newctx`: SM3, its size.
    ///
    /// # Safety
    /// `provctx` is the default provider's context; `propq` is NULL or a string.
    pub(crate) unsafe extern "C" fn sm2sig_newctx(provctx: *mut c_void, propq: *const c_char) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(Sm2Ctx {
            // SAFETY: the caller's guarantee.
            libctx: unsafe { libctx_of(provctx) },
            // SAFETY: the caller's guarantee.
            propq: (!propq.is_null()).then(|| unsafe { CStr::from_ptr(propq) }.to_owned()),
            ec: ptr::null_mut(),
            flag_compute_z_digest: false,
            mdname: OSSL_DIGEST_NAME_SM3.to_bytes().to_vec(),
            aid: Vec::new(),
            md: None,
            mdctx: ptr::null_mut(),
            mdsize: SM3_DIGEST_LENGTH,
            id: None,
        })
    }
}

ffi_callback! {
    /// `sm2sig_signature_init`: the key (or the one the context has), then the parameters.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `ec` is NULL or a live EC key; `params` is NULL or an
    /// array.
    pub(crate) unsafe extern "C" fn sm2sig_signature_init(vctx: *mut c_void, ec: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if ec.is_null() && c.ec.is_null() {
            err::raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET, "sm2sig_signature_init");
            return 0;
        }
        if !ec.is_null() {
            // SAFETY: the caller's live key.
            if unsafe { EC_KEY_up_ref(ec.cast()) } == 0 {
                return 0;
            }
            // SAFETY: the reference the context held, or NULL.
            unsafe { EC_KEY_free(c.ec) };
            c.ec = ec.cast();
        }
        // SAFETY: the caller's guarantee.
        unsafe { sm2sig_set_ctx_params(vctx, params) }
    }
}

ffi_callback! {
    /// `sm2sig_sign`: the DER signature of `tbs` (a number of the digest's size), or just the
    /// size for NULL `sig`.
    ///
    /// # Safety
    /// `vctx` is a live context; `sig` is NULL or has room for `sigsize` octets; `siglen` is
    /// writable; `tbs` holds `tbslen` octets.
    pub(crate) unsafe extern "C" fn sm2sig_sign(vctx: *mut c_void, sig: *mut c_uchar, siglen: *mut usize, sigsize: usize, tbs: *const c_uchar, tbslen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the context's key, or NULL.
        let ecsize = usize::try_from(unsafe { ECDSA_size(c.ec) }).unwrap_or(0);
        if sig.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { siglen.write(ecsize) };
            return 1;
        }
        if sigsize < ecsize || (c.mdsize != 0 && tbslen != c.mdsize) {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(dgst) = (unsafe { bytes(tbs, tbslen) }) else { return 0 };
        // SAFETY: the caller's room (at least the key's size); the context's key.
        match unsafe { internal_sign(dgst, sig, c.ec) } {
            Some(n) => {
                // SAFETY: the caller's guarantee.
                unsafe { siglen.write(n as usize) };
                1
            }
            None => 0,
        }
    }
}

ffi_callback! {
    /// `sm2sig_verify`: 1, 0, or -1 for a malformed signature.
    ///
    /// # Safety
    /// `vctx` is a live context; `sig` holds `siglen` octets; `tbs` holds `tbslen`.
    pub(crate) unsafe extern "C" fn sm2sig_verify(vctx: *mut c_void, sig: *const c_uchar, siglen: usize, tbs: *const c_uchar, tbslen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.mdsize != 0 && tbslen != c.mdsize {
            return 0;
        }
        // SAFETY: the caller's guarantee, for each.
        let (Some(s), Some(t)) = (unsafe { bytes(sig, siglen) }, unsafe { bytes(tbs, tbslen) }) else {
            return 0;
        };
        // OpenSSL passes the signature's length as an int; past INT_MAX it reads as negative,
        // which fails to decode.
        if c_int::try_from(s.len()).is_err() {
            return -1;
        }
        // SAFETY: the context's key.
        unsafe { internal_verify(t, s, c.ec) }
    }
}

ffi_callback! {
    /// `sm2sig_digest_signverify_init`: the Z value due again, the key and parameters, SM3,
    /// the algorithm identifier, and the digest context started.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `mdname` is NULL or a string; `ec` is NULL or a live
    /// EC key; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn sm2sig_digest_signverify_init(vctx: *mut c_void, mdname: *const c_char, ec: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        c.flag_compute_z_digest = true;
        // SAFETY: the caller's guarantee.
        if unsafe { sm2sig_signature_init(vctx, ec, params) } != 1 {
            return 0;
        }
        // SAFETY: the caller's string, or NULL.
        let name = (!mdname.is_null()).then(|| unsafe { CStr::from_ptr(mdname) });
        if !c.set_mdname(name) {
            return 0;
        }
        if c.mdctx.is_null() {
            // SAFETY: no preconditions.
            c.mdctx = unsafe { EVP_MD_CTX_new() };
            if c.mdctx.is_null() {
                return 0;
            }
        }
        let md = c.md.as_ref().map_or(ptr::null(), |m| m.ptr().cast_const());
        // SAFETY: the digest.
        let md_nid = unsafe { EVP_MD_get_type(md) };
        // `ossl_DER_w_algorithmIdentifier_SM2_with_MD`: only SM3 has one.
        c.aid = if md_nid == NID_sm3 {
            objects::object(NID_SM2_with_SM3)
                .and_then(|o| der(0x30, &der(0x06, o.der)?))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        // SAFETY: the context's digest context; the digest; the caller's parameters.
        c_int::from(unsafe { EVP_DigestInit_ex2(c.mdctx, md, params) } == 1)
    }
}

ffi_callback! {
    /// `sm2sig_digest_signverify_update`: the Z value first, then the data.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `data` holds `datalen` octets.
    pub(crate) unsafe extern "C" fn sm2sig_digest_signverify_update(vctx: *mut c_void, data: *const c_uchar, datalen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.mdctx.is_null() {
            return 0;
        }
        // SAFETY: the context's digest context; the caller's data.
        c_int::from(c.compute_z() && unsafe { EVP_DigestUpdate(c.mdctx, data.cast(), datalen) } != 0)
    }
}

/// The message's digest: the Z value (if not yet fed), then the digest context finished.
fn finish(c: &mut Sm2Ctx) -> Option<([u8; 64], usize)> {
    let mut digest = [0u8; 64];
    let mut dlen: c_uint = 0;
    if !c.compute_z() {
        return None;
    }
    // SAFETY: the context's digest context; room for any digest.
    if unsafe { EVP_DigestFinal_ex(c.mdctx, digest.as_mut_ptr(), &raw mut dlen) } == 0 {
        return None;
    }
    Some((digest, usize::try_from(dlen).ok()?))
}

ffi_callback! {
    /// `sm2sig_digest_sign_final`: the message's digest signed (only the size for NULL `sig`).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `sig` is NULL or has room for `sigsize` octets;
    /// `siglen` is writable.
    pub(crate) unsafe extern "C" fn sm2sig_digest_sign_final(vctx: *mut c_void, sig: *mut c_uchar, siglen: *mut usize, sigsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.mdctx.is_null() {
            return 0;
        }
        let (digest, dlen) = if sig.is_null() {
            ([0u8; 64], 0)
        } else {
            let Some(d) = finish(c) else { return 0 };
            d
        };
        // SAFETY: the caller's guarantee; the digest's octets.
        unsafe { sm2sig_sign(vctx, sig, siglen, sigsize, digest.as_ptr(), dlen) }
    }
}

ffi_callback! {
    /// `sm2sig_digest_verify_final`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `sig` holds `siglen` octets.
    pub(crate) unsafe extern "C" fn sm2sig_digest_verify_final(vctx: *mut c_void, sig: *const c_uchar, siglen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.mdctx.is_null() {
            return 0;
        }
        let md = c.md.as_ref().map_or(ptr::null(), |m| m.ptr().cast_const());
        // SAFETY: the digest, or NULL.
        let md_size = unsafe { EVP_MD_get_size(md) };
        if !(1..=64).contains(&md_size) {
            return 0;
        }
        let Some((digest, dlen)) = finish(c) else { return 0 };
        // SAFETY: the caller's guarantee; the digest's octets.
        unsafe { sm2sig_verify(vctx, sig, siglen, digest.as_ptr(), dlen) }
    }
}

ffi_callback! {
    /// `sm2sig_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context the caller gives up.
    pub(crate) unsafe extern "C" fn sm2sig_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<Sm2Ctx>(vctx) };
    }
}

ffi_callback! {
    /// `sm2sig_dupctx`: references to the key and digest, copies of the digest context and ID.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn sm2sig_dupctx(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return ptr::null_mut() };
        // SAFETY: the context's key, or NULL.
        if !c.ec.is_null() && unsafe { EC_KEY_up_ref(c.ec) } == 0 {
            return ptr::null_mut();
        }
        let mut copy = Sm2Ctx {
            libctx: c.libctx,
            propq: c.propq.clone(),
            ec: c.ec,
            flag_compute_z_digest: c.flag_compute_z_digest,
            mdname: c.mdname.clone(),
            aid: c.aid.clone(),
            md: c.md.clone(),
            mdctx: ptr::null_mut(),
            mdsize: c.mdsize,
            id: c.id.clone(),
        };
        if !c.mdctx.is_null() {
            // SAFETY: no preconditions.
            copy.mdctx = unsafe { EVP_MD_CTX_new() };
            // SAFETY: the new context; the context's.
            if copy.mdctx.is_null() || unsafe { EVP_MD_CTX_copy_ex(copy.mdctx, c.mdctx) } != 1 {
                return ptr::null_mut();
            }
        }
        boxed(copy)
    }
}

ffi_callback! {
    /// `sm2sig_get_ctx_params`: the algorithm identifier (failing without one), the digest's
    /// size and name.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn sm2sig_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::SM2SIG_GET_CTX_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let find = |key: &CStr| {
            // SAFETY: the caller's array; a static name.
            unsafe { OSSL_PARAM_locate(params, key.as_ptr()) }
        };
        let p = find(OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if !p.is_null() {
            let aid = if c.aid.is_empty() { ptr::null() } else { c.aid.as_ptr() };
            // SAFETY: a parameter of the array; the identifier, or NULL (which fails).
            if unsafe { OSSL_PARAM_set_octet_string(p, aid.cast(), c.aid.len()) } != 1 {
                return 0;
            }
        }
        let p = find(OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
        // SAFETY: a parameter of the array.
        if !p.is_null() && unsafe { OSSL_PARAM_set_size_t(p, c.mdsize) } != 1 {
            return 0;
        }
        let p = find(OSSL_SIGNATURE_PARAM_DIGEST);
        if !p.is_null() {
            let given = CString::new(c.mdname.clone()).unwrap_or_default();
            let name = match &c.md {
                // SAFETY: the context's digest.
                Some(m) => unsafe { EVP_MD_get0_name(m.ptr()) },
                None => given.as_ptr(),
            };
            // SAFETY: a parameter of the array; a string.
            if unsafe { OSSL_PARAM_set_utf8_string(p, name) } != 1 {
                return 0;
            }
        }
        1
    }
}

/// `known_gettable_ctx_params`.
static GETTABLE: Params<4> = Params([
    defn(
        OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    defn(
        OSSL_SIGNATURE_PARAM_DIGEST_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_SIGNATURE_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `sm2sig_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn sm2sig_gettable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `sm2sig_set_ctx_params`: the ID (only before the Z value is computed), the digest's size
    /// (SM3's only), and the digest (SM3 only).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn sm2sig_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::SM2SIG_SET_CTX_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        let find = |key: &CStr| {
            // SAFETY: the caller's array; a static name.
            unsafe { locate(params, key) }
        };
        if let Some(p) = find(OSSL_PKEY_PARAM_DIST_ID) {
            if !c.flag_compute_z_digest {
                return 0;
            }
            let mut id = Vec::new();
            if p.data_size != 0 {
                let mut data: *mut c_void = ptr::null_mut();
                let mut n: usize = 0;
                // SAFETY: a parameter of the array; a place for a new allocation.
                if unsafe { OSSL_PARAM_get_octet_string(p, &raw mut data, 0, &raw mut n) } != 1 {
                    return 0;
                }
                // SAFETY: the allocation just made holds `n` octets.
                id = unsafe { bytes(data.cast::<u8>(), n) }.unwrap_or_default().to_vec();
                // SAFETY: the allocation just made, freed once.
                unsafe { mem::release(data) };
            }
            c.id = Some(id);
        }
        if let Some(p) = find(OSSL_SIGNATURE_PARAM_DIGEST_SIZE) {
            let mut mdsize: usize = 0;
            // SAFETY: a parameter of the array; a local.
            if unsafe { OSSL_PARAM_get_size_t(p, &raw mut mdsize) } != 1 || mdsize != c.mdsize {
                return 0;
            }
        }
        if let Some(p) = find(OSSL_SIGNATURE_PARAM_DIGEST) {
            let mut name: *mut c_char = ptr::null_mut();
            // SAFETY: a parameter of the array; a place for a new allocation.
            if unsafe { OSSL_PARAM_get_utf8_string(p, &raw mut name, 0) } != 1 {
                return 0;
            }
            // SAFETY: the string just made.
            let owned = unsafe { CStr::from_ptr(name) }.to_owned();
            // SAFETY: the allocation just made, freed once.
            unsafe { mem::release(name.cast()) };
            if !c.set_mdname(Some(&owned)) {
                return 0;
            }
        }
        1
    }
}

/// `known_settable_ctx_params`.
static SETTABLE: Params<4> = Params([
    defn(
        OSSL_SIGNATURE_PARAM_DIGEST_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_SIGNATURE_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_PKEY_PARAM_DIST_ID, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `sm2sig_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn sm2sig_settable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `sm2sig_get_ctx_md_params`.
    ///
    /// # Safety
    /// `vctx` is a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn sm2sig_get_ctx_md_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.mdctx.is_null() {
            return 0;
        }
        // SAFETY: the context's digest context; the caller's array.
        unsafe { EVP_MD_CTX_get_params(c.mdctx, params) }
    }
}

ffi_callback! {
    /// `sm2sig_set_ctx_md_params`.
    ///
    /// # Safety
    /// `vctx` is a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn sm2sig_set_ctx_md_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.mdctx.is_null() {
            return 0;
        }
        // SAFETY: the context's digest context; the caller's array.
        unsafe { EVP_MD_CTX_set_params(c.mdctx, params) }
    }
}

ffi_callback! {
    /// `sm2sig_gettable_ctx_md_params`.
    ///
    /// # Safety
    /// `vctx` is a live context.
    pub(crate) unsafe extern "C" fn sm2sig_gettable_ctx_md_params(vctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        match unsafe { ctx(vctx) }.and_then(|c| c.md.as_ref()) {
            // SAFETY: the context's digest.
            Some(m) => unsafe { EVP_MD_gettable_ctx_params(m.ptr()) },
            None => ptr::null(),
        }
    }
}

ffi_callback! {
    /// `sm2sig_settable_ctx_md_params`.
    ///
    /// # Safety
    /// `vctx` is a live context.
    pub(crate) unsafe extern "C" fn sm2sig_settable_ctx_md_params(vctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        match unsafe { ctx(vctx) }.and_then(|c| c.md.as_ref()) {
            // SAFETY: the context's digest.
            Some(m) => unsafe { EVP_MD_settable_ctx_params(m.ptr()) },
            None => ptr::null(),
        }
    }
}

type NewCtxFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type InitFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
type SignFn = unsafe extern "C" fn(
    *mut c_void,
    *mut c_uchar,
    *mut usize,
    usize,
    *const c_uchar,
    usize,
) -> c_int;
type VerifyFn =
    unsafe extern "C" fn(*mut c_void, *const c_uchar, usize, *const c_uchar, usize) -> c_int;
type DigestInitFn =
    unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_void, *const OSSL_PARAM) -> c_int;
type UpdateFn = unsafe extern "C" fn(*mut c_void, *const c_uchar, usize) -> c_int;
type SignFinalFn = unsafe extern "C" fn(*mut c_void, *mut c_uchar, *mut usize, usize) -> c_int;
type VerifyFinalFn = unsafe extern "C" fn(*mut c_void, *const c_uchar, usize) -> c_int;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;
type MdListFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;

/// `ossl_sm2_signature_functions`.
pub(crate) static SM2_SIGNATURE: Dispatch<22> = Dispatch([
    entry!(OSSL_FUNC_SIGNATURE_NEWCTX, sm2sig_newctx, NewCtxFn),
    entry!(OSSL_FUNC_SIGNATURE_SIGN_INIT, sm2sig_signature_init, InitFn),
    entry!(OSSL_FUNC_SIGNATURE_SIGN, sm2sig_sign, SignFn),
    entry!(
        OSSL_FUNC_SIGNATURE_VERIFY_INIT,
        sm2sig_signature_init,
        InitFn
    ),
    entry!(OSSL_FUNC_SIGNATURE_VERIFY, sm2sig_verify, VerifyFn),
    entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        sm2sig_digest_signverify_init,
        DigestInitFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        sm2sig_digest_signverify_update,
        UpdateFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        sm2sig_digest_sign_final,
        SignFinalFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
        sm2sig_digest_signverify_init,
        DigestInitFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
        sm2sig_digest_signverify_update,
        UpdateFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
        sm2sig_digest_verify_final,
        VerifyFinalFn
    ),
    entry!(OSSL_FUNC_SIGNATURE_FREECTX, sm2sig_freectx, FreeCtxFn),
    entry!(OSSL_FUNC_SIGNATURE_DUPCTX, sm2sig_dupctx, DupCtxFn),
    entry!(
        OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        sm2sig_get_ctx_params,
        GetParamsFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        sm2sig_gettable_ctx_params,
        ListFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        sm2sig_set_ctx_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        sm2sig_settable_ctx_params,
        ListFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
        sm2sig_get_ctx_md_params,
        GetParamsFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
        sm2sig_gettable_ctx_md_params,
        MdListFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
        sm2sig_set_ctx_md_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
        sm2sig_settable_ctx_md_params,
        MdListFn
    ),
    END,
]);
