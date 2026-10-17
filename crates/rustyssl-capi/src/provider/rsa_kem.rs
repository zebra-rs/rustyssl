//! The default provider's RSA KEM (`rsa_kem.c`): RSASVE (SP 800-56B 7.2.1), whose secret is a
//! random number z with 1 < z < n - 1, sent encrypted with the public key and no padding.
//!
//! As in OpenSSL, copying a context gives an empty one (OpenSSL's `rsakem_dupctx` copies
//! nothing: no key, no library context), and the secret buffer is taken to hold the key's
//! size, as the caller learns it from the size query.

use core::ffi::{CStr, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PROV, ERR_LIB_RSA, EVP_PKEY_OP_DECAPSULATE, EVP_PKEY_OP_ENCAPSULATE,
    OSSL_FUNC_KEM_DECAPSULATE, OSSL_FUNC_KEM_DECAPSULATE_INIT, OSSL_FUNC_KEM_DUPCTX,
    OSSL_FUNC_KEM_ENCAPSULATE, OSSL_FUNC_KEM_ENCAPSULATE_INIT, OSSL_FUNC_KEM_FREECTX,
    OSSL_FUNC_KEM_GET_CTX_PARAMS, OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS, OSSL_FUNC_KEM_NEWCTX,
    OSSL_FUNC_KEM_SET_CTX_PARAMS, OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, OSSL_KEM_PARAM_OPERATION,
    OSSL_KEM_PARAM_OPERATION_RSASVE, OSSL_LIB_CTX, OSSL_PARAM, OSSL_PARAM_UTF8_STRING,
    PROV_R_BAD_LENGTH, PROV_R_INVALID_KEY, PROV_R_INVALID_OUTPUT_LENGTH, RSA, RSA_NO_PADDING,
    RSA_R_DATA_TOO_LARGE_FOR_MODULUS, RSA_R_DATA_TOO_SMALL,
};
use rustyssl_crypto::bn::{self as core_bn, BigNum, Endian};

use super::builtin::libctx_of;
use super::macs::{boxed, context, is_empty, locate, unbox};
use super::rsa_sig::key_op_allowed;
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::err;
use crate::ffi::{bytes, ffi_callback};
use crate::rsa::{RsaState, rsa};
use crate::rsa_gen::Env;
use crate::rsa_ops::{Op, method_op};

/// `KEM_OP_RSASVE`, the only operation.
const OP_RSASVE: c_int = 0;

/// `PROV_RSA_CTX` (KEM).
struct KemCtx {
    #[expect(
        dead_code,
        reason = "OpenSSL's context keeps it; the key's own is used"
    )]
    libctx: *mut OSSL_LIB_CTX,
    /// The key, with a reference this holds.
    rsa: *mut RSA,
    op: c_int,
}

impl Drop for KemCtx {
    fn drop(&mut self) {
        // SAFETY: the reference this holds, or NULL.
        unsafe { crate::rsa::free(self.rsa) };
    }
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `rsakem_newctx`.
unsafe fn ctx<'a>(vctx: *mut c_void) -> Option<&'a mut KemCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { context::<KemCtx>(vctx) }
}

impl KemCtx {
    /// The key's state and library context, if there's a key.
    fn key(&self) -> Option<(RsaState, *mut OSSL_LIB_CTX)> {
        // SAFETY: the reference this holds, or NULL.
        unsafe { rsa(self.rsa) }.map(|r| (r.snapshot(), r.libctx.get()))
    }
}

ffi_callback! {
    /// `rsakem_newctx`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context.
    pub(crate) unsafe extern "C" fn rsakem_newctx(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(KemCtx {
            // SAFETY: the caller's guarantee.
            libctx: unsafe { libctx_of(provctx) },
            rsa: ptr::null_mut(),
            op: OP_RSASVE,
        })
    }
}

ffi_callback! {
    /// `rsakem_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context the caller gives up.
    pub(crate) unsafe extern "C" fn rsakem_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<KemCtx>(vctx) };
    }
}

ffi_callback! {
    /// `rsakem_dupctx`: an empty context, as OpenSSL's (which copies nothing of the source).
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn rsakem_dupctx(_vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(KemCtx {
            libctx: ptr::null_mut(),
            rsa: ptr::null_mut(),
            op: OP_RSASVE,
        })
    }
}

/// `rsakem_init`.
///
/// # Safety
/// `vctx` is NULL or a live context; `vrsa` is NULL or live key data; `params` is NULL or an
/// array.
unsafe fn init(
    vctx: *mut c_void,
    vrsa: *mut c_void,
    params: *const OSSL_PARAM,
    operation: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx(vctx) }) else {
        return 0;
    };
    // SAFETY: the caller's guarantee.
    let Some(r) = (unsafe { rsa(vrsa.cast()) }) else {
        return 0;
    };
    let kind = r.lock().kind;
    if !key_op_allowed(kind, operation) {
        return 0;
    }
    // SAFETY: the caller's live key data.
    if !unsafe { crate::rsa::up_ref(vrsa.cast()) } {
        return 0;
    }
    // SAFETY: the reference the context held, or NULL.
    unsafe { crate::rsa::free(c.rsa) };
    c.rsa = vrsa.cast();
    let e_ok = r
        .lock()
        .key
        .e
        .as_ref()
        .is_some_and(|e| core_bn::cmp(e, &BigNum::one()).is_gt());
    if !e_ok {
        err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY, "rsakem_init");
        return 0;
    }
    // SAFETY: the caller's guarantee.
    unsafe { rsakem_set_ctx_params(vctx, params) }
}

ffi_callback! {
    /// `rsakem_encapsulate_init`.
    ///
    /// # Safety
    /// As for `init`.
    pub(crate) unsafe extern "C" fn rsakem_encapsulate_init(vctx: *mut c_void, vrsa: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { init(vctx, vrsa, params, EVP_PKEY_OP_ENCAPSULATE) }
    }
}

ffi_callback! {
    /// `rsakem_decapsulate_init`.
    ///
    /// # Safety
    /// As for `init`.
    pub(crate) unsafe extern "C" fn rsakem_decapsulate_init(vctx: *mut c_void, vrsa: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { init(vctx, vrsa, params, EVP_PKEY_OP_DECAPSULATE) }
    }
}

ffi_callback! {
    /// `rsakem_get_ctx_params`: nothing to get (outside FIPS).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn rsakem_get_ctx_params(vctx: *mut c_void, _params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        c_int::from(!vctx.is_null())
    }
}

/// `known_gettable_rsakem_ctx_params` (empty outside FIPS) and
/// `known_settable_rsakem_ctx_params`.
static GETTABLE: Params<1> = Params([PARAM_END]);
static SETTABLE: Params<2> = Params([
    defn(OSSL_KEM_PARAM_OPERATION, OSSL_PARAM_UTF8_STRING as c_int, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `rsakem_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn rsakem_gettable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `rsakem_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn rsakem_settable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `rsakem_set_ctx_params`: the operation, by name (any case); an unknown one fails.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn rsakem_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's array; a static name.
        if let Some(p) = unsafe { locate(params, OSSL_KEM_PARAM_OPERATION) } {
            if p.data_type != OSSL_PARAM_UTF8_STRING as u32 || p.data.is_null() {
                return 0;
            }
            // SAFETY: a UTF-8 string parameter's data is a string.
            let name = unsafe { CStr::from_ptr(p.data.cast()) };
            if !name.to_bytes().eq_ignore_ascii_case(OSSL_KEM_PARAM_OPERATION_RSASVE.to_bytes()) {
                return 0;
            }
            c.op = OP_RSASVE;
        }
        1
    }
}

/// The key's size in octets (`RSA_size`: 0 without a modulus).
fn key_size(st: &RsaState) -> usize {
    st.key.n.as_ref().map_or(0, BigNum::num_bytes)
}

/// The sizes written where asked for.
///
/// # Safety
/// `outlen` and `secretlen` are NULL or writable.
unsafe fn write_sizes(outlen: *mut usize, secretlen: *mut usize, nlen: usize) {
    if !outlen.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { outlen.write(nlen) };
    }
    if !secretlen.is_null() {
        // SAFETY: as above.
        unsafe { secretlen.write(nlen) };
    }
}

/// `rsasve_generate`.
///
/// # Safety
/// `out` is NULL or has room for the key's size; `outlen` and `secretlen` are NULL or
/// writable; `secret` has room for the key's size when `out` isn't NULL.
unsafe fn generate(
    c: &KemCtx,
    out: *mut c_uchar,
    outlen: *mut usize,
    secret: *mut c_uchar,
    secretlen: *mut usize,
) -> c_int {
    const F: &str = "rsasve_generate";
    let Some((st, libctx)) = c.key() else {
        return 0;
    };
    let nlen = key_size(&st);
    if out.is_null() {
        if nlen == 0 {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY, F);
            return 0;
        }
        if outlen.is_null() && secretlen.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { write_sizes(outlen, secretlen, nlen) };
        return 1;
    }
    // SAFETY: the caller's guarantee.
    if !outlen.is_null() && unsafe { outlen.read() } < nlen {
        err::raise(ERR_LIB_PROV, PROV_R_INVALID_OUTPUT_LENGTH, F);
        return 0;
    }
    if secret.is_null() {
        return 0;
    }
    // SAFETY: the caller's room for the key's size.
    let out = unsafe { core::slice::from_raw_parts_mut(out, nlen) };
    // SAFETY: as above.
    let secret_buf = unsafe { core::slice::from_raw_parts_mut(secret, nlen) };
    // `rsasve_gen_rand_bytes`: z = 2 + a random number below n - 3, padded to the key's size.
    let z = st.key.n.as_ref().and_then(|n| {
        let mut nm3 = n.clone();
        nm3.sub_word(3).ok()?;
        // SAFETY: the key's library context; no callback.
        let env = unsafe { Env::new(libctx, ptr::null_mut()) }?;
        let mut z = env.rand_range(&nm3)?;
        z.add_word(2).ok()?;
        z.to_bin(Some(nlen), Endian::Big, false)
    });
    let Some(z) = z else { return 0 };
    secret_buf.copy_from_slice(&z);
    // SAFETY: the context's key.
    let r = unsafe { method_op(c.rsa, Op::PublicEncrypt, secret_buf, out, RSA_NO_PADDING) };
    if r != Ok(nlen) {
        secret_buf.fill(0);
        return 0;
    }
    // SAFETY: the caller's guarantee.
    unsafe { write_sizes(outlen, secretlen, nlen) };
    1
}

/// `rsasve_recover`.
///
/// # Safety
/// `out` is NULL or has room for the key's size; `outlen` is NULL or writable; `input` holds
/// `inlen` octets.
unsafe fn recover(
    c: &KemCtx,
    out: *mut c_uchar,
    outlen: *mut usize,
    input: *const c_uchar,
    inlen: usize,
) -> c_int {
    const F: &str = "rsasve_recover";
    let Some((st, _)) = c.key() else {
        return 0;
    };
    let nlen = key_size(&st);
    if out.is_null() {
        if nlen == 0 {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY, F);
            return 0;
        }
        // SAFETY: the caller's guarantee: NULL or a live `size_t`.
        if let Some(l) = unsafe { outlen.as_mut() } {
            *l = nlen;
        }
        return 1;
    }
    if inlen != nlen {
        err::raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH, F);
        return 0;
    }
    // SAFETY: the caller's guarantee.
    if !outlen.is_null() && unsafe { outlen.read() } < nlen {
        err::raise(ERR_LIB_PROV, PROV_R_INVALID_OUTPUT_LENGTH, F);
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let Some(input) = (unsafe { bytes(input, inlen) }) else {
        return 0;
    };
    // The ciphertext must be over 1 and under n - 1.
    let (Some(n), Ok(cv)) = (
        st.key.n.as_ref(),
        BigNum::from_bin(input, Endian::Big, false),
    ) else {
        return 0;
    };
    let mut nm1 = n.clone();
    if nm1.sub_word(1).is_err() {
        return 0;
    }
    let reason = if core_bn::ucmp(&cv, &BigNum::one()).is_le() {
        RSA_R_DATA_TOO_SMALL
    } else if core_bn::ucmp(&cv, &nm1).is_ge() {
        RSA_R_DATA_TOO_LARGE_FOR_MODULUS
    } else {
        0
    };
    if reason != 0 {
        err::raise(ERR_LIB_RSA, reason, F);
        return 0;
    }
    // SAFETY: the caller's room for the key's size.
    let out = unsafe { core::slice::from_raw_parts_mut(out, nlen) };
    // SAFETY: the context's key.
    let r =
        unsafe { method_op(c.rsa, Op::PrivateDecrypt, input, out, RSA_NO_PADDING) }.unwrap_or(0);
    if r > 0 && !outlen.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { outlen.write(nlen) };
    }
    c_int::from(r > 0)
}

ffi_callback! {
    /// `rsakem_generate`: the encapsulated secret and the secret (only their sizes for NULL
    /// `out`).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; as for `generate`.
    pub(crate) unsafe extern "C" fn rsakem_generate(vctx: *mut c_void, out: *mut c_uchar, outlen: *mut usize, secret: *mut c_uchar, secretlen: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        match c.op {
            // SAFETY: the caller's guarantee.
            OP_RSASVE => unsafe { generate(c, out, outlen, secret, secretlen) },
            _ => -2,
        }
    }
}

ffi_callback! {
    /// `rsakem_recover`: the secret from its encapsulation (only success for NULL `out`).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; as for `recover`.
    pub(crate) unsafe extern "C" fn rsakem_recover(vctx: *mut c_void, out: *mut c_uchar, outlen: *mut usize, input: *const c_uchar, inlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        match c.op {
            // SAFETY: the caller's guarantee.
            OP_RSASVE => unsafe { recover(c, out, outlen, input, inlen) },
            _ => -2,
        }
    }
}

type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type InitFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
type EncapsulateFn =
    unsafe extern "C" fn(*mut c_void, *mut c_uchar, *mut usize, *mut c_uchar, *mut usize) -> c_int;
type DecapsulateFn =
    unsafe extern "C" fn(*mut c_void, *mut c_uchar, *mut usize, *const c_uchar, usize) -> c_int;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

/// `ossl_rsa_asym_kem_functions`.
pub(crate) static RSA_KEM: Dispatch<12> = Dispatch([
    entry!(OSSL_FUNC_KEM_NEWCTX, rsakem_newctx, NewCtxFn),
    entry!(
        OSSL_FUNC_KEM_ENCAPSULATE_INIT,
        rsakem_encapsulate_init,
        InitFn
    ),
    entry!(OSSL_FUNC_KEM_ENCAPSULATE, rsakem_generate, EncapsulateFn),
    entry!(
        OSSL_FUNC_KEM_DECAPSULATE_INIT,
        rsakem_decapsulate_init,
        InitFn
    ),
    entry!(OSSL_FUNC_KEM_DECAPSULATE, rsakem_recover, DecapsulateFn),
    entry!(OSSL_FUNC_KEM_FREECTX, rsakem_freectx, FreeCtxFn),
    entry!(OSSL_FUNC_KEM_DUPCTX, rsakem_dupctx, DupCtxFn),
    entry!(
        OSSL_FUNC_KEM_GET_CTX_PARAMS,
        rsakem_get_ctx_params,
        GetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS,
        rsakem_gettable_ctx_params,
        ListFn
    ),
    entry!(
        OSSL_FUNC_KEM_SET_CTX_PARAMS,
        rsakem_set_ctx_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
        rsakem_settable_ctx_params,
        ListFn
    ),
    END,
]);
