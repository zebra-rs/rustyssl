//! The default provider's EdDSA signatures (`eddsa_sig.c`): Ed25519 and its variants Ed25519ctx
//! and Ed25519ph (RFC 8032), signing and verifying a whole message at once.
//!
//! The context follows OpenSSL's. Each algorithm presets its instance: ED25519ph and ED25519ctx
//! refuse the `instance` parameter, while ED25519 (through a digest init or a plain init) takes
//! it. A plain sign or verify init expects the caller to have prehashed, so it works only once
//! the instance is Ed25519ph. An instance that doesn't fit the key is ignored. The algorithm
//! identifier is `SEQUENCE { id-Ed25519 }`.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, NID_ED25519, OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
    OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, OSSL_FUNC_SIGNATURE_DUPCTX,
    OSSL_FUNC_SIGNATURE_FREECTX, OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, OSSL_FUNC_SIGNATURE_NEWCTX,
    OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES, OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, OSSL_FUNC_SIGNATURE_SIGN,
    OSSL_FUNC_SIGNATURE_SIGN_INIT, OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
    OSSL_FUNC_SIGNATURE_VERIFY, OSSL_FUNC_SIGNATURE_VERIFY_INIT,
    OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, OSSL_LIB_CTX, OSSL_PARAM, OSSL_PARAM_OCTET_STRING,
    OSSL_PARAM_UTF8_STRING, OSSL_SIGNATURE_PARAM_ALGORITHM_ID, OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
    OSSL_SIGNATURE_PARAM_INSTANCE, PROV_R_FAILED_TO_SIGN, PROV_R_INVALID_DIGEST,
    PROV_R_INVALID_DIGEST_LENGTH, PROV_R_INVALID_EDDSA_INSTANCE_FOR_ATTEMPTED_OPERATION,
    PROV_R_INVALID_PREHASHED_DIGEST_LENGTH, PROV_R_NO_INSTANCE_ALLOWED, PROV_R_NO_KEY_SET,
    PROV_R_NOT_A_PRIVATE_KEY, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
};
use rustyssl_asn1::objects;
use rustyssl_crypto::ecx::{Dom, ED25519_SIGSIZE};

use super::builtin::libctx_of;
use super::macs::{boxed, context, is_empty, locate, unbox, wipe};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::ecx::{self, EcxKey, EcxType, sha512_available};
use crate::err;
use crate::evp::md_ctx::EVP_Q_digest;
use crate::ffi::{bytes, ffi_callback};
use crate::params::{
    OSSL_PARAM_get_octet_string, OSSL_PARAM_get_utf8_string, OSSL_PARAM_locate,
    OSSL_PARAM_set_octet_string,
};

/// `OSSL_MAX_NAME_SIZE`.
const MAX_NAME: usize = 50;

/// `EDDSA_MAX_CONTEXT_STRING_LEN`.
const MAX_CONTEXT: usize = 255;

/// `EDDSA_PREHASH_OUTPUT_LEN`.
const PREHASH_LEN: usize = 64;

/// `ID_EdDSA_INSTANCE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Instance {
    Ed25519,
    Ed25519ctx,
    Ed25519ph,
}

impl Instance {
    /// The instances by name, as `eddsa_set_ctx_params` matches them (ignoring case); Ed448's
    /// are known but never fit an Ed25519 key.
    const NAMES: [(&'static str, Option<Self>); 5] = [
        ("Ed25519", Some(Self::Ed25519)),
        ("Ed25519ctx", Some(Self::Ed25519ctx)),
        ("Ed25519ph", Some(Self::Ed25519ph)),
        ("Ed448", None),
        ("Ed448ph", None),
    ];
}

/// `PROV_EDDSA_CTX`.
#[derive(Clone)]
struct EddsaCtx {
    libctx: *mut OSSL_LIB_CTX,
    /// The key (key data with a reference this holds), or NULL.
    key: *mut c_void,
    aid: Vec<u8>,
    instance: Option<Instance>,
    /// The instance and its flags are fixed by the algorithm.
    instance_preset: bool,
    /// For ph instances, the caller gives the prehash.
    prehash_by_caller: bool,
    dom2: bool,
    prehash: bool,
    /// A non-empty context string is required (Ed25519ctx).
    context_required: bool,
    context: Vec<u8>,
}

impl Drop for EddsaCtx {
    fn drop(&mut self) {
        // SAFETY: the reference this holds, or NULL.
        unsafe { ecx::free(self.key) };
    }
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `eddsa_newctx`.
unsafe fn ctx<'a>(vctx: *mut c_void) -> Option<&'a mut EddsaCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { context::<EddsaCtx>(vctx) }
}

impl EddsaCtx {
    /// The context's key.
    fn key(&self) -> Option<&EcxKey> {
        // SAFETY: the reference this holds, or NULL.
        unsafe { ecx::key(self.key) }
    }

    /// `eddsa_setup_instance`: whether the instance fits the key (then set with its flags).
    fn setup_instance(&mut self, instance: Instance, preset: bool, by_caller: bool) -> bool {
        if self.key().map(|k| k.kind) != Some(EcxType::Ed25519) {
            return false;
        }
        (self.dom2, self.prehash, self.context_required) = match instance {
            Instance::Ed25519 => (false, false, false),
            Instance::Ed25519ctx => (true, false, true),
            Instance::Ed25519ph => (true, true, false),
        };
        self.instance = Some(instance);
        self.instance_preset = preset;
        self.prehash_by_caller = by_caller;
        true
    }

    /// The hashes' start for `ossl_ed25519_sign` and `ossl_ed25519_verify`.
    fn dom(&self) -> Dom<'_> {
        Dom {
            dom2: self.dom2,
            ph: self.prehash,
            cs: self.context_required,
            context: &self.context,
        }
    }

    /// The message as the signature covers it: SHA-512's prehash of `tbs` for a ph instance
    /// (or the caller's, checked), `tbs` otherwise (refused if the caller meant to prehash).
    fn message(&self, tbs: &[u8], f: &str) -> Option<Vec<u8>> {
        if self.prehash {
            if self.prehash_by_caller {
                if tbs.len() != PREHASH_LEN {
                    err::raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH, f);
                    return None;
                }
                return Some(tbs.to_vec());
            }
            let mut md = [0u8; 64];
            let mut mdlen = 0;
            // SAFETY: the context's library context; a static name; the message; room for
            // SHA-512's digest.
            let ok = unsafe {
                EVP_Q_digest(
                    self.libctx,
                    c"SHA512".as_ptr(),
                    ptr::null(),
                    tbs.as_ptr().cast(),
                    tbs.len(),
                    md.as_mut_ptr(),
                    &raw mut mdlen,
                )
            };
            if ok == 0 || mdlen != PREHASH_LEN {
                err::raise(ERR_LIB_PROV, PROV_R_INVALID_PREHASHED_DIGEST_LENGTH, f);
                return None;
            }
            return Some(md.to_vec());
        }
        if self.prehash_by_caller {
            err::raise(
                ERR_LIB_PROV,
                PROV_R_INVALID_EDDSA_INSTANCE_FOR_ATTEMPTED_OPERATION,
                f,
            );
            return None;
        }
        Some(tbs.to_vec())
    }
}

/// `ossl_DER_w_algorithmIdentifier_ED25519`: `SEQUENCE { OID }`.
fn ed25519_aid() -> Vec<u8> {
    let Some(oid) = objects::object(NID_ED25519).map(|o| o.der) else {
        return Vec::new();
    };
    let (Ok(n), Ok(m)) = (
        u8::try_from(oid.len()),
        u8::try_from(oid.len().saturating_add(2)),
    ) else {
        return Vec::new();
    };
    let mut v = vec![0x30, m, 0x06, n];
    v.extend_from_slice(oid);
    v
}

ffi_callback! {
    /// `eddsa_newctx`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context.
    pub(crate) unsafe extern "C" fn eddsa_newctx(provctx: *mut c_void, _propq: *const c_char) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(EddsaCtx {
            // SAFETY: the caller's guarantee.
            libctx: unsafe { libctx_of(provctx) },
            key: ptr::null_mut(),
            aid: Vec::new(),
            instance: None,
            instance_preset: false,
            prehash_by_caller: false,
            dom2: false,
            prehash: false,
            context_required: false,
            context: Vec::new(),
        })
    }
}

/// `eddsa_signverify_init`: the key, the flags and the context string reset, and the
/// algorithm identifier.
///
/// # Safety
/// `c` is a live context; `vedkey` is NULL or live ECX key data.
unsafe fn signverify_init(c: &mut EddsaCtx, vedkey: *mut c_void) -> bool {
    const F: &str = "eddsa_signverify_init";
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { ecx::key(vedkey) }) else {
        err::raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET, F);
        return false;
    };
    let aid = match k.kind {
        EcxType::Ed25519 => ed25519_aid(),
        _ => {
            err::raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, F);
            return false;
        }
    };
    // SAFETY: the caller's live key.
    unsafe { ecx::up_ref(vedkey) };
    // SAFETY: the reference the context held, or NULL.
    unsafe { ecx::free(c.key) };
    c.key = vedkey;
    c.instance_preset = false;
    c.dom2 = false;
    c.prehash = false;
    c.context_required = false;
    c.context.clear();
    c.aid = aid;
    true
}

/// An init: the key, the instance with its flags, then the parameters.
///
/// # Safety
/// `vctx` is NULL or a live context; `vedkey` is NULL or live ECX key data; `params` is NULL
/// or an array.
unsafe fn init(
    vctx: *mut c_void,
    vedkey: *mut c_void,
    params: *const OSSL_PARAM,
    instance: Instance,
    preset: bool,
    by_caller: bool,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx(vctx) }) else {
        return 0;
    };
    // SAFETY: the caller's guarantee.
    if !unsafe { signverify_init(c, vedkey) } || !c.setup_instance(instance, preset, by_caller) {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    unsafe { eddsa_set_ctx_params(vctx, params) }
}

/// Defines an init callback of an instance.
macro_rules! eddsa_init {
    ($name:ident, $doc:literal, $instance:ident, $preset:literal, $by_caller:literal) => {
        ffi_callback! {
            #[doc = $doc]
            ///
            /// # Safety
            /// `vctx` is NULL or a live context; `vedkey` is NULL or live ECX key data;
            /// `params` is NULL or an array.
            pub(crate) unsafe extern "C" fn $name(vctx: *mut c_void, vedkey: *mut c_void, params: *const OSSL_PARAM) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { init(vctx, vedkey, params, Instance::$instance, $preset, $by_caller) }
            }
        }
    };
}

eddsa_init!(
    ed25519_signverify_message_init,
    "`ed25519_signverify_message_init`.",
    Ed25519,
    true,
    false
);
eddsa_init!(
    ed25519ph_signverify_message_init,
    "`ed25519ph_signverify_message_init`.",
    Ed25519ph,
    true,
    false
);
eddsa_init!(
    ed25519ph_signverify_init,
    "`ed25519ph_signverify_init`: the caller prehashes.",
    Ed25519ph,
    true,
    true
);
eddsa_init!(
    ed25519_signverify_init,
    "`ed25519_signverify_init`: the caller prehashes, so it signs once the instance is \
     Ed25519ph.",
    Ed25519,
    false,
    true
);
eddsa_init!(
    ed25519ctx_signverify_message_init,
    "`ed25519ctx_signverify_message_init`.",
    Ed25519ctx,
    true,
    false
);

ffi_callback! {
    /// `ed25519_digest_signverify_init`: no digest may be named; without a key, only the
    /// parameters (on a context with one).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `mdname` is NULL or a string; `vedkey` is NULL or live
    /// ECX key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ed25519_digest_signverify_init(vctx: *mut c_void, mdname: *const c_char, vedkey: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !mdname.is_null() && unsafe { *mdname } != 0 {
            err::raise_with_text(
                ERR_LIB_PROV,
                PROV_R_INVALID_DIGEST,
                "ed25519_digest_signverify_init",
                "Explicit digest not allowed with EdDSA operations",
            );
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if vedkey.is_null() && !c.key.is_null() {
            // SAFETY: the caller's guarantee.
            return unsafe { eddsa_set_ctx_params(vctx, params) };
        }
        // SAFETY: the caller's guarantee.
        unsafe { init(vctx, vedkey, params, Instance::Ed25519, false, false) }
    }
}

ffi_callback! {
    /// `ed25519_sign`: the signature's size when `sigret` is NULL, else the signature.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `sigret` is NULL or has room for `sigsize` octets;
    /// `siglen` is writable; `tbs` holds `tbslen` octets.
    pub(crate) unsafe extern "C" fn ed25519_sign(vctx: *mut c_void, sigret: *mut c_uchar, siglen: *mut usize, sigsize: usize, tbs: *const c_uchar, tbslen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "ed25519_sign";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if sigret.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { siglen.write(ED25519_SIGSIZE) };
            return 1;
        }
        if sigsize < ED25519_SIGSIZE {
            err::raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL, F);
            return 0;
        }
        let Some(k) = c.key() else { return 0 };
        let (public, private) = {
            let s = k.lock();
            let public = <[u8; 32]>::try_from(s.pubkey.get(..32).unwrap_or_default()).ok();
            let private = s.privkey.as_deref().map(|p| <[u8; 32]>::try_from(p).ok());
            (public, private)
        };
        let Some(private) = private else {
            err::raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY, F);
            return 0;
        };
        // SAFETY: the caller's guarantee.
        let Some(tbs) = (unsafe { bytes(tbs, tbslen) }) else { return 0 };
        let Some(msg) = c.message(tbs, F) else { return 0 };
        let sig = match (private, public) {
            (Some(mut s), Some(p)) if sha512_available(c.libctx, None) => {
                let sig = rustyssl_crypto::ecx::ed25519_sign(&msg, &p, &s, &c.dom());
                wipe(&mut s);
                sig
            }
            (Some(mut s), _) => {
                wipe(&mut s);
                None
            }
            _ => None,
        };
        let Some(sig) = sig else {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN, F);
            return 0;
        };
        // SAFETY: the caller's room for `sigsize` (at least 64) octets; a local.
        unsafe { ptr::copy_nonoverlapping(sig.as_ptr(), sigret, sig.len()) };
        // SAFETY: the caller's guarantee.
        unsafe { siglen.write(ED25519_SIGSIZE) };
        1
    }
}

ffi_callback! {
    /// `ed25519_verify`: whether `sig` (of exactly 64 octets) signs `tbs`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `sig` holds `siglen` octets; `tbs` holds `tbslen`
    /// octets.
    pub(crate) unsafe extern "C" fn ed25519_verify(vctx: *mut c_void, sig: *const c_uchar, siglen: usize, tbs: *const c_uchar, tbslen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if siglen != ED25519_SIGSIZE {
            return 0;
        }
        let Some(k) = c.key() else { return 0 };
        let (public, propq) = {
            let s = k.lock();
            (<[u8; 32]>::try_from(s.pubkey.get(..32).unwrap_or_default()).ok(), s.propq.clone())
        };
        // SAFETY: the caller's guarantee.
        let Some(sig) = (unsafe { bytes(sig, siglen) }) else { return 0 };
        // SAFETY: as above.
        let Some(tbs) = (unsafe { bytes(tbs, tbslen) }) else { return 0 };
        let Some(msg) = c.message(tbs, "ed25519_verify") else { return 0 };
        let (Ok(sig), Some(public)) = (<&[u8; ED25519_SIGSIZE]>::try_from(sig), public) else {
            return 0;
        };
        if !sha512_available(c.libctx, propq.as_deref()) {
            return 0;
        }
        c_int::from(rustyssl_crypto::ecx::ed25519_verify(&msg, sig, &public, &c.dom()))
    }
}

ffi_callback! {
    /// `eddsa_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context the caller gives up.
    pub(crate) unsafe extern "C" fn eddsa_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<EddsaCtx>(vctx) };
    }
}

ffi_callback! {
    /// `eddsa_dupctx`: a copy with a reference to the key.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn eddsa_dupctx(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return ptr::null_mut() };
        if !c.key.is_null() {
            // SAFETY: the context's live key.
            unsafe { ecx::up_ref(c.key) };
        }
        boxed(c.clone())
    }
}

/// `ed25519_sigalg_query_key_types`'s list.
struct KeyTypes([*const c_char; 2]);
// SAFETY: pointers to static strings.
unsafe impl Sync for KeyTypes {}
static ED25519_KEY_TYPES: KeyTypes = KeyTypes([c"ED25519".as_ptr(), ptr::null()]);

ffi_callback! {
    /// `ed25519_sigalg_query_key_types`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ed25519_sigalg_query_key_types() -> *const *const c_char
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        ED25519_KEY_TYPES.0.as_ptr()
    }
}

ffi_callback! {
    /// `eddsa_get_ctx_params`: the algorithm identifier (failing without one).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn eddsa_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the caller's array; a static name.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID.as_ptr()) };
        if !p.is_null() {
            let aid = if c.aid.is_empty() { ptr::null() } else { c.aid.as_ptr() };
            // SAFETY: a parameter of the array; the identifier, or NULL (which fails).
            if unsafe { OSSL_PARAM_set_octet_string(p, aid.cast(), c.aid.len()) } != 1 {
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
    defn(OSSL_SIGNATURE_PARAM_INSTANCE, OSSL_PARAM_UTF8_STRING, 0),
    defn(
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `eddsa_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn eddsa_gettable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `eddsa_set_ctx_params`: the instance (unless preset; one that doesn't fit the key is
    /// ignored) and the context string (at most 255 octets; a failure empties it).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn eddsa_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "eddsa_set_ctx_params";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's array; a static name.
        if let Some(p) = unsafe { locate(params, OSSL_SIGNATURE_PARAM_INSTANCE) } {
            if c.instance_preset {
                err::raise_with_text(
                    ERR_LIB_PROV,
                    PROV_R_NO_INSTANCE_ALLOWED,
                    F,
                    "the EdDSA instance is preset, you may not try to specify it",
                );
                return 0;
            }
            let mut buf = [0 as c_char; MAX_NAME];
            let mut s = buf.as_mut_ptr();
            // SAFETY: a parameter of the array; the buffer.
            if unsafe { OSSL_PARAM_get_utf8_string(p, &raw mut s, MAX_NAME) } != 1 {
                return 0;
            }
            // SAFETY: NUL-terminated by the call.
            let name = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_bytes();
            let Some((_, instance)) = Instance::NAMES
                .iter()
                .find(|(n, _)| n.as_bytes().eq_ignore_ascii_case(name))
            else {
                err::raise_with_text(
                    ERR_LIB_PROV,
                    PROV_R_INVALID_EDDSA_INSTANCE_FOR_ATTEMPTED_OPERATION,
                    F,
                    &format!("unknown INSTANCE name: {}", String::from_utf8_lossy(name)),
                );
                return 0;
            };
            if let Some(i) = *instance {
                let by_caller = c.prehash_by_caller;
                c.setup_instance(i, false, by_caller);
            }
        }
        // SAFETY: the caller's array; a static name.
        if let Some(p) = unsafe { locate(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING) } {
            let mut buf = [0u8; MAX_CONTEXT];
            let mut data = buf.as_mut_ptr().cast::<c_void>();
            let mut n = 0;
            // SAFETY: a parameter of the array; the buffer.
            if unsafe { OSSL_PARAM_get_octet_string(p, &raw mut data, MAX_CONTEXT, &raw mut n) } != 1 {
                c.context.clear();
                return 0;
            }
            c.context = buf.get(..n).unwrap_or_default().to_vec();
        }
        1
    }
}

/// `settable_ctx_params`.
static SETTABLE: Params<3> = Params([
    defn(OSSL_SIGNATURE_PARAM_INSTANCE, OSSL_PARAM_UTF8_STRING, 0),
    defn(
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    PARAM_END,
]);

/// `settable_variant_ctx_params`.
static SETTABLE_VARIANT: Params<2> = Params([
    defn(
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `eddsa_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn eddsa_settable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `eddsa_settable_variant_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn eddsa_settable_variant_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE_VARIANT.0.as_ptr()
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
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type KeyTypesFn = unsafe extern "C" fn() -> *const *const c_char;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

/// `IMPL_EDDSA_DISPATCH(vn, ed25519)`: a table's common start, with `vn`'s message init.
macro_rules! eddsa_dispatch {
    ($n:literal, $name:ident, $doc:literal, $message_init:ident, [$($rest:expr),* $(,)?]) => {
        #[doc = $doc]
        pub(crate) static $name: Dispatch<$n> = Dispatch([
            entry!(OSSL_FUNC_SIGNATURE_NEWCTX, eddsa_newctx, NewCtxFn),
            entry!(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, $message_init, InitFn),
            entry!(OSSL_FUNC_SIGNATURE_SIGN, ed25519_sign, SignFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, $message_init, InitFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY, ed25519_verify, VerifyFn),
            entry!(OSSL_FUNC_SIGNATURE_FREECTX, eddsa_freectx, FreeCtxFn),
            entry!(OSSL_FUNC_SIGNATURE_DUPCTX, eddsa_dupctx, DupCtxFn),
            entry!(OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES, ed25519_sigalg_query_key_types, KeyTypesFn),
            $($rest,)*
            entry!(OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, eddsa_get_ctx_params, GetParamsFn),
            entry!(OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, eddsa_gettable_ctx_params, ListFn),
            entry!(OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, eddsa_set_ctx_params, SetParamsFn),
            END,
        ]);
    };
}

eddsa_dispatch!(
    19,
    ED25519_SIGNATURE,
    "`ossl_ed25519_signature_functions`.",
    ed25519_signverify_message_init,
    [
        entry!(
            OSSL_FUNC_SIGNATURE_SIGN_INIT,
            ed25519_signverify_init,
            InitFn
        ),
        entry!(
            OSSL_FUNC_SIGNATURE_VERIFY_INIT,
            ed25519_signverify_init,
            InitFn
        ),
        entry!(
            OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
            ed25519_digest_signverify_init,
            DigestInitFn
        ),
        entry!(OSSL_FUNC_SIGNATURE_DIGEST_SIGN, ed25519_sign, SignFn),
        entry!(
            OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
            ed25519_digest_signverify_init,
            DigestInitFn
        ),
        entry!(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, ed25519_verify, VerifyFn),
        entry!(
            OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
            eddsa_settable_ctx_params,
            ListFn
        ),
    ]
);

eddsa_dispatch!(
    17,
    ED25519PH_SIGNATURE,
    "`ossl_ed25519ph_signature_functions` (its second inits are never used, as in OpenSSL).",
    ed25519ph_signverify_message_init,
    [
        entry!(
            OSSL_FUNC_SIGNATURE_SIGN_INIT,
            ed25519ph_signverify_init,
            InitFn
        ),
        entry!(
            OSSL_FUNC_SIGNATURE_VERIFY_INIT,
            ed25519ph_signverify_init,
            InitFn
        ),
        entry!(
            OSSL_FUNC_SIGNATURE_SIGN_INIT,
            ed25519ph_signverify_message_init,
            InitFn
        ),
        entry!(
            OSSL_FUNC_SIGNATURE_VERIFY_INIT,
            ed25519ph_signverify_message_init,
            InitFn
        ),
        entry!(
            OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
            eddsa_settable_variant_ctx_params,
            ListFn
        ),
    ]
);

eddsa_dispatch!(
    15,
    ED25519CTX_SIGNATURE,
    "`ossl_ed25519ctx_signature_functions`.",
    ed25519ctx_signverify_message_init,
    [
        entry!(
            OSSL_FUNC_SIGNATURE_SIGN_INIT,
            ed25519ctx_signverify_message_init,
            InitFn
        ),
        entry!(
            OSSL_FUNC_SIGNATURE_VERIFY_INIT,
            ed25519ctx_signverify_message_init,
            InitFn
        ),
        entry!(
            OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
            eddsa_settable_variant_ctx_params,
            ListFn
        ),
    ]
);
