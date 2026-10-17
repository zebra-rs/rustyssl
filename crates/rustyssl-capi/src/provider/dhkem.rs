//! The default provider's DHKEMs (`ec_kem.c`, `ecx_kem.c`; RFC 9180, 4.1): the EC KEM over
//! P-256, P-384, and P-521 and the ECX KEM over X25519 and X448, in their one mode, "DHKEM",
//! with and without a sender's authentication key.
//!
//! An encapsulation makes an ephemeral key (from the context's input key material, else from
//! random octets), exchanges it with the recipient's key (and the sender's authentication key
//! with the recipient's), and extracts and expands the shared secret over the KEM's suite with
//! both encoded public keys (and the authentication key's) as context; a decapsulation does the
//! same from the ephemeral public key it's given. As OpenSSL's, the KDF is HKDF of the KEM's
//! digest, the ephemeral key has no properties, and a key whose group isn't a KEM's fails the
//! initialization with -2.

use core::ffi::{c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    EC_GROUP, EC_KEY, ERR_LIB_PROV, EVP_PKEY_OP_DECAPSULATE, EVP_PKEY_OP_ENCAPSULATE,
    OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT, OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT,
    OSSL_FUNC_KEM_DECAPSULATE, OSSL_FUNC_KEM_DECAPSULATE_INIT, OSSL_FUNC_KEM_ENCAPSULATE,
    OSSL_FUNC_KEM_ENCAPSULATE_INIT, OSSL_FUNC_KEM_FREECTX, OSSL_FUNC_KEM_NEWCTX,
    OSSL_FUNC_KEM_SET_CTX_PARAMS, OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, OSSL_KEM_PARAM_IKME,
    OSSL_KEM_PARAM_OPERATION, OSSL_KEM_PARAM_OPERATION_DHKEM, OSSL_LIB_CTX, OSSL_PARAM,
    OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UTF8_STRING, OSSL_PKEY_PARAM_PUB_KEY,
    POINT_CONVERSION_UNCOMPRESSED, PROV_R_BAD_LENGTH, PROV_R_FAILED_DURING_DERIVATION,
    PROV_R_INVALID_KEY, PROV_R_MISMATCHING_DOMAIN_PARAMETERS, PROV_R_MISSING_KEY,
    PROV_R_NOT_A_PUBLIC_KEY,
};
use rustyssl_crypto::bn::Zeroizing;
use rustyssl_crypto::ec::dhkem::{self, ECX_KEMS, Kem};

use super::builtin::libctx_of;
use super::macs::{boxed, context, is_empty, locate, unbox};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::ec::key::{
    EC_KEY_free, EC_KEY_get0_group, EC_KEY_get0_private_key, EC_KEY_get0_public_key, EC_KEY_new_ex,
    EC_KEY_oct2key, EC_KEY_set_group, EC_KEY_up_ref,
};
use crate::ecx::{self, EcxType};
use crate::err;
use crate::ffi::{bytes, ffi_callback};

/// `OSSL_HPKE_MAX_PUBLIC`: the largest encoded public key (P-521's).
const MAX_PUBLIC: usize = 133;

/// A KEM's sizes (`OSSL_HPKE_KEM_INFO`): `Npk` (= `Nenc`) besides the core table's.
#[derive(Clone, Copy)]
struct Info {
    kem: &'static Kem,
    /// The encoded public key's length (an uncompressed point, or the ECX key).
    npk: usize,
}

impl Info {
    fn nsecret(self) -> usize {
        self.kem.secret_len
    }
    fn nsk(self) -> usize {
        self.kem.private_len
    }
}

/// The context's keys: EC keys with a reference each, or ECX key data with one.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Ec,
    Ecx,
}

/// `PROV_EC_CTX` and `PROV_ECX_CTX`.
struct KemCtx {
    family: Family,
    libctx: *mut OSSL_LIB_CTX,
    recipient: *mut c_void,
    auth: *mut c_void,
    op: c_int,
    ikm: Option<Zeroizing<Vec<u8>>>,
    info: Option<Info>,
}

/// Frees a key of the family (NULL does nothing).
fn free_key(family: Family, k: *mut c_void) {
    match family {
        // SAFETY: a reference this holds, or NULL.
        Family::Ec => unsafe { EC_KEY_free(k.cast()) },
        // SAFETY: as above.
        Family::Ecx => unsafe { ecx::free(k) },
    }
}

/// Takes a reference to a key of the family.
///
/// # Safety
/// `k` is a live key of the family.
unsafe fn up_ref(family: Family, k: *mut c_void) -> bool {
    match family {
        // SAFETY: the caller's guarantee.
        Family::Ec => (unsafe { EC_KEY_up_ref(k.cast()) }) == 1,
        Family::Ecx => {
            // SAFETY: as above.
            unsafe { ecx::up_ref(k) };
            true
        }
    }
}

impl Drop for KemCtx {
    fn drop(&mut self) {
        free_key(self.family, self.recipient);
        free_key(self.family, self.auth);
    }
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from a `newctx` here.
unsafe fn ctx<'a>(vctx: *mut c_void) -> Option<&'a mut KemCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { context::<KemCtx>(vctx) }
}

fn newctx(provctx: *mut c_void, family: Family) -> *mut c_void {
    boxed(KemCtx {
        family,
        // SAFETY: the provider's context.
        libctx: unsafe { libctx_of(provctx) },
        recipient: ptr::null_mut(),
        auth: ptr::null_mut(),
        op: 0,
        ikm: None,
        info: None,
    })
}

ffi_callback! {
    /// `eckem_newctx`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context.
    pub(crate) unsafe extern "C" fn eckem_newctx(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        newctx(provctx, Family::Ec)
    }
}

ffi_callback! {
    /// `ecxkem_newctx`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context.
    pub(crate) unsafe extern "C" fn ecxkem_newctx(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        newctx(provctx, Family::Ecx)
    }
}

ffi_callback! {
    /// `eckem_freectx` and `ecxkem_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context the caller gives up.
    pub(crate) unsafe extern "C" fn dhkem_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<KemCtx>(vctx) };
    }
}

/// The EC key's KEM: its curve's (`ec_curvename_get0` and `ossl_HPKE_KEM_INFO_find_curve`).
///
/// # Safety
/// `ec` is a live EC key.
unsafe fn ec_info(ec: *const EC_KEY) -> Option<Info> {
    // SAFETY: the caller's key.
    let group = unsafe { EC_KEY_get0_group(ec) };
    if group.is_null() {
        return None;
    }
    // SAFETY: the key's group.
    let nid = unsafe { crate::ec::group::EC_GROUP_get_curve_name(group) };
    // SAFETY: no preconditions.
    let name = unsafe { crate::ec::curves::EC_curve_nid2nist(nid) };
    if name.is_null() {
        return None;
    }
    // SAFETY: a static name of the table.
    let name = unsafe { core::ffi::CStr::from_ptr(name) };
    let Some(kem) = dhkem::kem_by_curve(name.to_bytes()) else {
        err::raise(
            ERR_LIB_PROV,
            rustyssl_abi::PROV_R_INVALID_CURVE,
            "ossl_HPKE_KEM_INFO_find_curve",
        );
        return None;
    };
    Some(Info {
        kem,
        npk: 1 + 2 * kem.private_len,
    })
}

/// The ECX key's KEM (`get_kem_info`): X25519's, else X448's.
fn ecx_info(k: &ecx::EcxKey) -> Info {
    let kem = if k.kind == EcxType::X25519 {
        &ECX_KEMS[0]
    } else {
        &ECX_KEMS[1]
    };
    Info {
        kem,
        npk: kem.private_len,
    }
}

/// `eckey_check`: the key has a public key, and a private key nonzero modulo the order (when
/// it has one; it needs one when `requires_private`).
///
/// # Safety
/// `ec` is a live EC key.
unsafe fn eckey_check(ec: *const EC_KEY, requires_private: bool) -> bool {
    // SAFETY: the caller's key.
    if unsafe { EC_KEY_get0_public_key(ec) }.is_null() {
        err::raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY, "eckey_check");
        return false;
    }
    // SAFETY: as above.
    let priv_key = unsafe { EC_KEY_get0_private_key(ec) };
    if priv_key.is_null() {
        return !requires_private;
    }
    // SAFETY: as above.
    let group = unsafe { EC_KEY_get0_group(ec) };
    // SAFETY: the key's group.
    let order = unsafe { crate::ec::group::EC_GROUP_get0_order(group) };
    // SAFETY: no preconditions.
    let bnctx = unsafe { crate::bn::ctx::BN_CTX_new_ex(ptr::null_mut()) };
    // SAFETY: as above.
    let rem = unsafe { crate::bn::BN_new() };
    let ok = !order.is_null()
        && !rem.is_null()
        && !bnctx.is_null()
        // SAFETY: the numbers; the context.
        && unsafe { crate::bn::arith::BN_nnmod(rem, priv_key, order, bnctx) } != 0
        // SAFETY: the remainder.
        && unsafe { crate::bn::BN_is_zero(rem) } == 0;
    // SAFETY: made above, or NULL.
    unsafe { crate::bn::BN_free(rem) };
    // SAFETY: as above.
    unsafe { crate::bn::ctx::BN_CTX_free(bnctx) };
    ok
}

/// `ecx_key_check`: the key has a private key when `requires_private`.
fn ecx_key_check(k: &ecx::EcxKey, requires_private: bool) -> bool {
    k.lock().privkey.is_some() || !requires_private
}

/// `eckem_init` and `ecxkem_init`: the recipient's key (-2 for one of no KEM's group), the
/// sender's authentication key (with the same parameters), the operation, and the parameters.
///
/// # Safety
/// `vctx` is NULL or a live context; `vkey` and `vauth` are NULL or live keys of its family;
/// `params` is NULL or an array.
unsafe fn init(
    vctx: *mut c_void,
    operation: c_int,
    vkey: *mut c_void,
    vauth: *mut c_void,
    params: *const OSSL_PARAM,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx(vctx) }) else {
        return 0;
    };
    if vkey.is_null() {
        return 0;
    }
    let decap = operation == EVP_PKEY_OP_DECAPSULATE;
    let encap = operation == EVP_PKEY_OP_ENCAPSULATE;
    let info = match c.family {
        Family::Ec => {
            // SAFETY: the caller's key.
            if !unsafe { eckey_check(vkey.cast(), decap) } {
                return 0;
            }
            // SAFETY: as above.
            unsafe { ec_info(vkey.cast()) }
        }
        Family::Ecx => {
            // SAFETY: as above.
            let Some(k) = (unsafe { ecx::key(vkey) }) else {
                return 0;
            };
            if !ecx_key_check(k, decap) {
                return 0;
            }
            Some(ecx_info(k))
        }
    };
    // `recipient_key_set`.
    free_key(
        c.family,
        core::mem::replace(&mut c.recipient, ptr::null_mut()),
    );
    let Some(info) = info else { return -2 };
    c.info = Some(info);
    // SAFETY: the caller's key.
    if !unsafe { up_ref(c.family, vkey) } {
        return 0;
    }
    c.recipient = vkey;
    if !vauth.is_null() {
        let ok = match c.family {
            Family::Ec => {
                // SAFETY: the caller's key.
                let g1 = unsafe { EC_KEY_get0_group(vkey.cast()) };
                // SAFETY: as above.
                let g2 = unsafe { EC_KEY_get0_group(vauth.cast()) };
                // SAFETY: as above.
                let same = !g1.is_null() && !g2.is_null() && unsafe { groups_equal(g1, g2) };
                if !same {
                    err::raise(
                        ERR_LIB_PROV,
                        PROV_R_MISMATCHING_DOMAIN_PARAMETERS,
                        "ossl_ec_match_params",
                    );
                }
                // SAFETY: as above.
                same && unsafe { eckey_check(vauth.cast(), encap) }
            }
            Family::Ecx => {
                // SAFETY: the caller's keys.
                let a = unsafe { ecx::key(vauth) };
                // SAFETY: as above.
                let r = unsafe { ecx::key(vkey) };
                match (a, r) {
                    (Some(a), Some(r)) => {
                        a.kind == r.kind && a.keylen() == r.keylen() && ecx_key_check(a, encap)
                    }
                    _ => false,
                }
            }
        };
        // `sender_authkey_set`.
        free_key(c.family, core::mem::replace(&mut c.auth, ptr::null_mut()));
        // SAFETY: the caller's key.
        if !ok || !unsafe { up_ref(c.family, vauth) } {
            return 0;
        }
        c.auth = vauth;
    }
    c.op = operation;
    // SAFETY: the caller's guarantee.
    unsafe { set_params(c, params) }
}

/// `EC_GROUP_cmp(g1, g2) == 0`.
///
/// # Safety
/// The groups are live.
unsafe fn groups_equal(g1: *const EC_GROUP, g2: *const EC_GROUP) -> bool {
    // SAFETY: no preconditions.
    let bnctx = unsafe { crate::bn::ctx::BN_CTX_new_ex(ptr::null_mut()) };
    if bnctx.is_null() {
        return false;
    }
    // SAFETY: the caller's groups; the context.
    let r = unsafe { crate::ec::group::EC_GROUP_cmp(g1, g2, bnctx) };
    // SAFETY: made above.
    unsafe { crate::bn::ctx::BN_CTX_free(bnctx) };
    r == 0
}

/// `eckem_set_ctx_params`: the input key material (none for an empty one) and the operation
/// (DHKEM, in any case).
///
/// # Safety
/// `params` is NULL or an array.
unsafe fn set_params(c: &mut KemCtx, params: *const OSSL_PARAM) -> c_int {
    // SAFETY: the caller's guarantee.
    if unsafe { is_empty(params) } {
        return 1;
    }
    // SAFETY: as above; static names.
    if let Some(p) = unsafe { locate(params, OSSL_KEM_PARAM_IKME) } {
        let ikm = if !p.data.is_null() && p.data_size != 0 {
            if p.data_type != OSSL_PARAM_OCTET_STRING.cast_unsigned() {
                return 0;
            }
            // SAFETY: an octet string's data of its size.
            let Some(d) = (unsafe { bytes(p.data.cast(), p.data_size) }) else {
                return 0;
            };
            Some(Zeroizing::new(d.to_vec()))
        } else {
            None
        };
        c.ikm = ikm;
    }
    // SAFETY: as above.
    if let Some(p) = unsafe { locate(params, OSSL_KEM_PARAM_OPERATION) } {
        if p.data_type != OSSL_PARAM_UTF8_STRING.cast_unsigned() || p.data.is_null() {
            return 0;
        }
        // SAFETY: a UTF-8 string parameter's data, NUL-terminated.
        let name = unsafe { core::ffi::CStr::from_ptr(p.data.cast()) };
        if !name
            .to_bytes()
            .eq_ignore_ascii_case(OSSL_KEM_PARAM_OPERATION_DHKEM.to_bytes())
        {
            return 0;
        }
    }
    1
}

type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type InitFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
type AuthInitFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
type EncapsulateFn =
    unsafe extern "C" fn(*mut c_void, *mut c_uchar, *mut usize, *mut c_uchar, *mut usize) -> c_int;
type DecapsulateFn =
    unsafe extern "C" fn(*mut c_void, *mut c_uchar, *mut usize, *const c_uchar, usize) -> c_int;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

ffi_callback! {
    /// `eckem_encapsulate_init` and `ecxkem_encapsulate_init`.
    ///
    /// # Safety
    /// As for a KEM's `encapsulate_init`.
    pub(crate) unsafe extern "C" fn dhkem_encapsulate_init(vctx: *mut c_void, vkey: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { init(vctx, EVP_PKEY_OP_ENCAPSULATE, vkey, ptr::null_mut(), params) }
    }
}

ffi_callback! {
    /// `eckem_decapsulate_init` and `ecxkem_decapsulate_init`.
    ///
    /// # Safety
    /// As for a KEM's `decapsulate_init`.
    pub(crate) unsafe extern "C" fn dhkem_decapsulate_init(vctx: *mut c_void, vkey: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { init(vctx, EVP_PKEY_OP_DECAPSULATE, vkey, ptr::null_mut(), params) }
    }
}

ffi_callback! {
    /// `eckem_auth_encapsulate_init` and `ecxkem_auth_encapsulate_init`: with the sender's
    /// private authentication key.
    ///
    /// # Safety
    /// As for a KEM's `auth_encapsulate_init`.
    pub(crate) unsafe extern "C" fn dhkem_auth_encapsulate_init(vctx: *mut c_void, vkey: *mut c_void, vauth: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { init(vctx, EVP_PKEY_OP_ENCAPSULATE, vkey, vauth, params) }
    }
}

ffi_callback! {
    /// `eckem_auth_decapsulate_init` and `ecxkem_auth_decapsulate_init`: with the sender's
    /// public authentication key.
    ///
    /// # Safety
    /// As for a KEM's `auth_decapsulate_init`.
    pub(crate) unsafe extern "C" fn dhkem_auth_decapsulate_init(vctx: *mut c_void, vkey: *mut c_void, vauth: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { init(vctx, EVP_PKEY_OP_DECAPSULATE, vkey, vauth, params) }
    }
}

ffi_callback! {
    /// `eckem_set_ctx_params` and `ecxkem_set_ctx_params`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn dhkem_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: as above.
        unsafe { set_params(c, params) }
    }
}

/// `known_settable_eckem_ctx_params`.
static SETTABLE: Params<3> = Params([
    defn(OSSL_KEM_PARAM_OPERATION, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_KEM_PARAM_IKME, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `eckem_settable_ctx_params` and `ecxkem_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn dhkem_settable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE.0.as_ptr()
    }
}

/// `ecpubkey_todata`: the EC key's public key, uncompressed, or `None`.
///
/// # Safety
/// `ec` is a live EC key.
unsafe fn ec_pub(ec: *const EC_KEY) -> Option<Vec<u8>> {
    // SAFETY: the caller's key.
    let group = unsafe { EC_KEY_get0_group(ec) };
    // SAFETY: as above.
    let point = unsafe { EC_KEY_get0_public_key(ec) };
    let mut buf = [0u8; MAX_PUBLIC];
    // SAFETY: the key's group and point; room for `MAX_PUBLIC`.
    let n = unsafe {
        crate::ec::point::EC_POINT_point2oct(
            group,
            point,
            POINT_CONVERSION_UNCOMPRESSED,
            buf.as_mut_ptr(),
            buf.len(),
            ptr::null_mut(),
        )
    };
    (n != 0).then(|| buf.get(..n).unwrap_or_default().to_vec())
}

/// `ecx_pubkey`: the ECX key's public key, or `None` (with `PROV_R_NOT_A_PUBLIC_KEY`).
fn ecx_pub(k: Option<&ecx::EcxKey>) -> Option<Vec<u8>> {
    match k {
        Some(k) if k.lock().haspubkey => Some(k.public()),
        _ => {
            err::raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY, "ecx_pubkey");
            None
        }
    }
}

/// `generate_ecdhkm`: ECDH of `sender`'s private key and `peer`'s public key (checked) into
/// `secretsz` octets, which must be the field's length.
///
/// # Safety
/// The keys are live EC keys.
unsafe fn ecdhkm(
    sender: *const EC_KEY,
    peer: *const EC_KEY,
    secretsz: usize,
) -> Option<Zeroizing<Vec<u8>>> {
    // SAFETY: the caller's key.
    let group = unsafe { EC_KEY_get0_group(sender) };
    // SAFETY: the key's group.
    let degree = unsafe { crate::ec::group::EC_GROUP_get_degree(group) };
    let secretlen = usize::try_from(degree).unwrap_or(0).div_ceil(8);
    if secretlen != secretsz {
        err::raise_with_text(
            ERR_LIB_PROV,
            PROV_R_BAD_LENGTH,
            "generate_ecdhkm",
            "secretsz invalid",
        );
        return None;
    }
    // `check_publickey`.
    // SAFETY: the caller's key.
    let pk = unsafe { crate::ec::key::key(peer) }?;
    // SAFETY: no preconditions.
    let bnctx = unsafe { crate::bn::ctx::BN_CTX_new_ex(pk.get().libctx.0) };
    if bnctx.is_null() {
        return None;
    }
    // SAFETY: the key's fields; the context.
    let ok = unsafe { crate::ec::key::public_check(&pk.get(), bnctx) };
    // SAFETY: made above.
    unsafe { crate::bn::ctx::BN_CTX_free(bnctx) };
    if !ok {
        return None;
    }
    let mut out = Zeroizing::new(vec![0u8; secretlen]);
    // SAFETY: the caller's key.
    let peer_point = unsafe { EC_KEY_get0_public_key(peer) };
    // SAFETY: room for `secretlen`; the keys.
    let r = unsafe {
        crate::ec::ecdsa::ECDH_compute_key(
            out.as_mut_ptr().cast(),
            secretlen,
            peer_point,
            sender,
            None,
        )
    };
    (r > 0).then_some(out)
}

/// `generate_ecxdhkm` (`ossl_ecx_compute_key`): X25519 or X448 of `sender`'s private key and
/// `peer`'s public key.
fn ecxdhkm(sender: Option<&ecx::EcxKey>, peer: Option<&ecx::EcxKey>) -> Option<Zeroizing<Vec<u8>>> {
    const F: &str = "ossl_ecx_compute_key";
    let (Some(s), Some(p)) = (sender, peer) else {
        err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, F);
        return None;
    };
    let Some(private) = s.lock().privkey.clone().map(Zeroizing::new) else {
        err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, F);
        return None;
    };
    let public = {
        let ps = p.lock();
        ps.pubkey.get(..p.keylen()).unwrap_or_default().to_vec()
    };
    match ecx::exchange(&private, &public) {
        Some((secret, true)) => Some(Zeroizing::new(secret)),
        _ => {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_DURING_DERIVATION, F);
            None
        }
    }
}

/// `dhkem_extract_and_expand`: `ExtractAndExpand(dh, kem_context)` (RFC 9180, 4.1).
fn extract_and_expand(info: Info, dhkm: &[u8], kemctx: &[u8], out: &mut [u8]) -> bool {
    let mut prk = Zeroizing::new(vec![0u8; info.nsecret()]);
    dhkem::labeled_extract(info.kem, &[], b"eae_prk", dhkm, &mut prk).is_ok()
        && dhkem::labeled_expand(info.kem, &prk, b"shared_secret", kemctx, out).is_ok()
}

/// The two exchanges of `derive_secret` and the authentication key's encoding: for an
/// encapsulation, the ephemeral key with the recipient's and the authentication key with the
/// recipient's; for a decapsulation, the recipient's with the ephemeral one's and with the
/// authentication key's.
///
/// # Safety
/// The keys are live keys of the context's family (`ephemeral` the ephemeral key, private for
/// an encapsulation, public for a decapsulation).
unsafe fn derive_secret(
    c: &KemCtx,
    info: Info,
    ephemeral: *mut c_void,
    encap: bool,
    sender_pub: &[u8],
    recipient_pub: &[u8],
    secret: &mut [u8],
) -> bool {
    let auth = !c.auth.is_null();
    let (priv1, peer1, priv2, peer2) = if encap {
        (ephemeral, c.recipient, c.auth, c.recipient)
    } else {
        (c.recipient, ephemeral, c.recipient, c.auth)
    };
    let mut dhkm = Zeroizing::new(Vec::new());
    let authpub = match c.family {
        Family::Ec => {
            // SAFETY: the caller's keys.
            let Some(d) = (unsafe { ecdhkm(priv1.cast(), peer1.cast(), info.nsk()) }) else {
                return false;
            };
            dhkm.extend_from_slice(&d);
            if auth {
                // SAFETY: the context's key.
                let Some(ap) = (unsafe { ec_pub(c.auth.cast()) }) else {
                    return false;
                };
                if ap.len() != info.npk {
                    err::raise_with_text(
                        ERR_LIB_PROV,
                        PROV_R_INVALID_KEY,
                        "derive_secret",
                        "Invalid sender auth public key",
                    );
                    return false;
                }
                // SAFETY: as above.
                let Some(d) = (unsafe { ecdhkm(priv2.cast(), peer2.cast(), info.nsk()) }) else {
                    return false;
                };
                dhkm.extend_from_slice(&d);
                Some(ap)
            } else {
                None
            }
        }
        Family::Ecx => {
            // SAFETY: as above.
            let key = |k: *mut c_void| unsafe { ecx::key(k) };
            let Some(d) = ecxdhkm(key(priv1), key(peer1)) else {
                return false;
            };
            dhkm.extend_from_slice(&d);
            if auth {
                let Some(d) = ecxdhkm(key(priv2), key(peer2)) else {
                    return false;
                };
                dhkm.extend_from_slice(&d);
                let Some(ap) = ecx_pub(key(c.auth)) else {
                    return false;
                };
                Some(ap)
            } else {
                None
            }
        }
    };
    let mut kemctx = Vec::with_capacity(3 * info.npk);
    kemctx.extend_from_slice(sender_pub.get(..info.npk).unwrap_or(sender_pub));
    kemctx.extend_from_slice(recipient_pub.get(..info.npk).unwrap_or(recipient_pub));
    if let Some(ap) = &authpub {
        kemctx.extend_from_slice(ap.get(..info.npk).unwrap_or(ap));
    }
    extract_and_expand(info, &dhkm, &kemctx, secret)
}

/// `derivekey`: the ephemeral key, from `ikm` (random octets of a private key's length when
/// there's none), with no properties; NULL on failure.
///
/// # Safety
/// The context has a recipient's key.
unsafe fn derivekey(c: &KemCtx, info: Info) -> *mut c_void {
    let mut random = Zeroizing::new(Vec::new());
    let seed: &[u8] = match c.ikm.as_deref().filter(|i| !i.is_empty()) {
        Some(i) => i,
        None => {
            random.resize(info.nsk(), 0);
            // SAFETY: room for the octets.
            if unsafe {
                crate::rand_lib::RAND_priv_bytes_ex(c.libctx, random.as_mut_ptr(), random.len(), 0)
            } <= 0
            {
                return ptr::null_mut();
            }
            &random
        }
    };
    match c.family {
        Family::Ec => {
            // SAFETY: the context's library context.
            let key = unsafe { EC_KEY_new_ex(c.libctx, ptr::null()) };
            if key.is_null() {
                return ptr::null_mut();
            }
            // SAFETY: the context's key.
            let group = unsafe { EC_KEY_get0_group(c.recipient.cast()) };
            // SAFETY: the new key; the recipient's group.
            let ok = unsafe { EC_KEY_set_group(key, group) } != 0
                // SAFETY: the new key with its group.
                && unsafe { crate::ec::key::generate_dhkem(key, seed) };
            if !ok {
                // SAFETY: made above.
                unsafe { EC_KEY_free(key) };
                return ptr::null_mut();
            }
            key.cast()
        }
        Family::Ecx => {
            // SAFETY: the context's key.
            let Some(r) = (unsafe { ecx::key(c.recipient) }) else {
                return ptr::null_mut();
            };
            let key = ecx::new(c.libctx, r.kind, None);
            // SAFETY: the key just made.
            let Some(k) = (unsafe { ecx::key(key) }) else {
                return ptr::null_mut();
            };
            let ok = match dhkem::derive_ecx_private(info.kem, seed) {
                Ok(sk) => {
                    let mut s = k.lock();
                    s.privkey = Some(sk.to_vec());
                    let ok = ecx::public_from_private(k, &mut s);
                    s.haspubkey = ok;
                    ok
                }
                Err(dhkem::Error::ShortInput { len, min }) => {
                    let text = format!("ikm length is :{len}, should be at least {min}");
                    err::raise_with_text(
                        ERR_LIB_PROV,
                        rustyssl_abi::PROV_R_INVALID_INPUT_LENGTH,
                        "ossl_ecx_dhkem_derive_private",
                        &text,
                    );
                    false
                }
                Err(_) => false,
            };
            if !ok {
                // SAFETY: made above.
                unsafe { ecx::free(key) };
                return ptr::null_mut();
            }
            key
        }
    }
}

/// The recipient's encoded public key.
///
/// # Safety
/// The context has a recipient's key.
unsafe fn recipient_pub(c: &KemCtx) -> Option<Vec<u8>> {
    match c.family {
        // SAFETY: the context's key.
        Family::Ec => unsafe { ec_pub(c.recipient.cast()) },
        // SAFETY: as above.
        Family::Ecx => ecx_pub(unsafe { ecx::key(c.recipient) }),
    }
}

ffi_callback! {
    /// `eckem_encapsulate` and `ecxkem_encapsulate` (`dhkem_encap`): with `enc` NULL, the
    /// lengths (into whichever of `enclen` and `secretlen` isn't NULL); else the ephemeral
    /// public key into `enc` and the shared secret into `secret`, each with room of at least
    /// its length.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `enc` and `secret` are NULL or have room for
    /// `*enclen` and `*secretlen` octets; `enclen` and `secretlen` are NULL or live.
    pub(crate) unsafe extern "C" fn dhkem_encapsulate(vctx: *mut c_void, enc: *mut c_uchar, enclen: *mut usize, secret: *mut c_uchar, secretlen: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "dhkem_encap";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let Some(info) = c.info.filter(|_| !c.recipient.is_null()) else { return 0 };
        // SAFETY: the caller's guarantee.
        let el = unsafe { enclen.as_mut() };
        // SAFETY: as above.
        let sl = unsafe { secretlen.as_mut() };
        if enc.is_null() {
            if el.is_none() && sl.is_none() {
                return 0;
            }
            if let Some(el) = el {
                *el = info.npk;
            }
            if let Some(sl) = sl {
                *sl = info.nsecret();
            }
            return 1;
        }
        let (Some(el), Some(sl)) = (el, sl) else { return 0 };
        if *sl < info.nsecret() {
            err::raise_with_text(ERR_LIB_PROV, PROV_R_BAD_LENGTH, F, "*secretlen too small");
            return 0;
        }
        if *el < info.npk {
            err::raise_with_text(ERR_LIB_PROV, PROV_R_BAD_LENGTH, F, "*enclen too small");
            return 0;
        }
        // SAFETY: the context's recipient.
        let eph = unsafe { derivekey(c, info) };
        let ok = 'out: {
            let (sender_pub, rpub) = match c.family {
                Family::Ec => {
                    if eph.is_null() {
                        break 'out false;
                    }
                    // SAFETY: the keys.
                    let (Some(s), Some(r)) = (unsafe { ec_pub(eph.cast()) }, unsafe { recipient_pub(c) }) else { break 'out false };
                    if s.len() != info.npk || r.len() != s.len() {
                        err::raise_with_text(ERR_LIB_PROV, PROV_R_INVALID_KEY, F, "Invalid public key");
                        break 'out false;
                    }
                    (s, r)
                }
                Family::Ecx => {
                    // SAFETY: the ephemeral key, or NULL.
                    let s = ecx_pub(unsafe { ecx::key(eph) });
                    // SAFETY: the context's recipient.
                    let r = unsafe { recipient_pub(c) };
                    let (Some(s), Some(r)) = (s, r) else { break 'out false };
                    (s, r)
                }
            };
            // SAFETY: the caller's room of at least the secret's length.
            let out = unsafe { core::slice::from_raw_parts_mut(secret, info.nsecret()) };
            // SAFETY: the context's keys and the ephemeral one.
            if !unsafe { derive_secret(c, info, eph, true, &sender_pub, &rpub, out) } {
                break 'out false;
            }
            // SAFETY: the caller's room of at least the encoding's length.
            unsafe { ptr::copy_nonoverlapping(sender_pub.as_ptr(), enc, info.npk) };
            *el = info.npk;
            *sl = info.nsecret();
            true
        };
        free_key(c.family, eph);
        c_int::from(ok)
    }
}

/// `eckey_frompub` and `ecxkey_pubfromdata`: a public key of the recipient's group or type
/// from its encoding, or NULL.
///
/// # Safety
/// The context has a recipient's key.
unsafe fn key_from_pub(c: &KemCtx, enc: &[u8]) -> *mut c_void {
    match c.family {
        Family::Ec => {
            // SAFETY: the context's key.
            let Some(r) = (unsafe { crate::ec::key::key(c.recipient.cast()) }) else {
                return ptr::null_mut();
            };
            // SAFETY: the recipient's library context and properties.
            let key = unsafe { EC_KEY_new_ex(r.get().libctx.0, r.propq()) };
            if key.is_null() {
                return ptr::null_mut();
            }
            // SAFETY: the context's key.
            let group = unsafe { EC_KEY_get0_group(c.recipient.cast()) };
            // SAFETY: the new key; the recipient's group.
            let ok = unsafe { EC_KEY_set_group(key, group) } != 0
                // SAFETY: as above.
                && unsafe { EC_KEY_oct2key(key, enc.as_ptr(), enc.len(), ptr::null_mut()) } != 0;
            if !ok {
                // SAFETY: made above.
                unsafe { EC_KEY_free(key) };
                return ptr::null_mut();
            }
            key.cast()
        }
        Family::Ecx => {
            // SAFETY: the context's key.
            let Some(r) = (unsafe { ecx::key(c.recipient) }) else {
                return ptr::null_mut();
            };
            let key = ecx::new(c.libctx, r.kind, None);
            let params = [
                // SAFETY: a static name; the encoding, read during the call.
                unsafe {
                    crate::params::OSSL_PARAM_construct_octet_string(
                        OSSL_PKEY_PARAM_PUB_KEY.as_ptr(),
                        enc.as_ptr().cast_mut().cast(),
                        enc.len(),
                    )
                },
                // SAFETY: no preconditions.
                unsafe { crate::params::OSSL_PARAM_construct_end() },
            ];
            // SAFETY: the key just made; the parameters.
            let ok = unsafe { ecx::key(key) }
                .is_some_and(|k| unsafe { ecx::key_fromdata(k, params.as_ptr(), false) });
            if !ok {
                // SAFETY: made above.
                unsafe { ecx::free(key) };
                return ptr::null_mut();
            }
            key
        }
    }
}

ffi_callback! {
    /// `eckem_decapsulate` and `ecxkem_decapsulate` (`dhkem_decap`): with `secret` NULL, the
    /// secret's length; else the shared secret of the ephemeral public key `enc` (exactly a
    /// public key's length) into room of at least its length.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `secret` is NULL or has room for `*secretlen` octets;
    /// `secretlen` is live; `enc` holds `enclen` octets.
    pub(crate) unsafe extern "C" fn dhkem_decapsulate(vctx: *mut c_void, secret: *mut c_uchar, secretlen: *mut usize, enc: *const c_uchar, enclen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "dhkem_decap";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let Some(info) = c.info.filter(|_| !c.recipient.is_null()) else { return 0 };
        // SAFETY: the caller's guarantee.
        let Some(sl) = (unsafe { secretlen.as_mut() }) else { return 0 };
        if secret.is_null() {
            *sl = info.nsecret();
            return 1;
        }
        if *sl < info.nsecret() {
            err::raise_with_text(ERR_LIB_PROV, PROV_R_BAD_LENGTH, F, "*secretlen too small");
            return 0;
        }
        if enclen != info.npk {
            err::raise_with_text(ERR_LIB_PROV, PROV_R_INVALID_KEY, F, "Invalid enc public key");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(enc) = (unsafe { bytes(enc, enclen) }) else { return 0 };
        // SAFETY: the context's recipient.
        let eph = unsafe { key_from_pub(c, enc) };
        let ok = 'out: {
            if eph.is_null() {
                break 'out false;
            }
            // SAFETY: as above.
            let Some(rpub) = (unsafe { recipient_pub(c) }) else { break 'out false };
            if c.family == Family::Ec && rpub.len() != info.npk {
                err::raise_with_text(ERR_LIB_PROV, PROV_R_INVALID_KEY, F, "Invalid recipient public key");
                break 'out false;
            }
            // SAFETY: the caller's room of at least the secret's length.
            let out = unsafe { core::slice::from_raw_parts_mut(secret, info.nsecret()) };
            // SAFETY: the context's keys and the ephemeral one.
            if !unsafe { derive_secret(c, info, eph, false, enc, &rpub, out) } {
                break 'out false;
            }
            *sl = info.nsecret();
            true
        };
        free_key(c.family, eph);
        c_int::from(ok)
    }
}

/// A DHKEM's dispatch table (`ossl_ec_asym_kem_functions`, `ossl_ecx_asym_kem_functions`).
macro_rules! dhkem_table {
    ($table:ident, $newctx:ident) => {
        pub(crate) static $table: Dispatch<11> = Dispatch([
            entry!(OSSL_FUNC_KEM_NEWCTX, $newctx, NewCtxFn),
            entry!(
                OSSL_FUNC_KEM_ENCAPSULATE_INIT,
                dhkem_encapsulate_init,
                InitFn
            ),
            entry!(OSSL_FUNC_KEM_ENCAPSULATE, dhkem_encapsulate, EncapsulateFn),
            entry!(
                OSSL_FUNC_KEM_DECAPSULATE_INIT,
                dhkem_decapsulate_init,
                InitFn
            ),
            entry!(OSSL_FUNC_KEM_DECAPSULATE, dhkem_decapsulate, DecapsulateFn),
            entry!(OSSL_FUNC_KEM_FREECTX, dhkem_freectx, FreeCtxFn),
            entry!(
                OSSL_FUNC_KEM_SET_CTX_PARAMS,
                dhkem_set_ctx_params,
                SetParamsFn
            ),
            entry!(
                OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
                dhkem_settable_ctx_params,
                ListFn
            ),
            entry!(
                OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT,
                dhkem_auth_encapsulate_init,
                AuthInitFn
            ),
            entry!(
                OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT,
                dhkem_auth_decapsulate_init,
                AuthInitFn
            ),
            END,
        ]);
    };
}

dhkem_table!(EC_KEM, eckem_newctx);
dhkem_table!(ECX_KEM, ecxkem_newctx);
