//! The default provider's RSA asymmetric cipher (`rsa_enc.c`): `EVP_PKEY_encrypt` and
//! `EVP_PKEY_decrypt` with PKCS #1 v1.5 (implicit rejection on by default), OAEP (with its
//! digest, MGF1 digest, and label), no padding, and TLS's premaster-secret decryption.
//!
//! As in OpenSSL, encryption returns -1 (not 0) when the RSA operation fails, decryption sets
//! the output length only on success (chosen in constant time), and the TLS mode always gives
//! 48 octets, random ones when the padding or version is wrong.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, EVP_PKEY_OP_DECRYPT, EVP_PKEY_OP_ENCRYPT,
    OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
    OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
    OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
    OSSL_ASYM_CIPHER_PARAM_PAD_MODE, OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION,
    OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, OSSL_FUNC_ASYM_CIPHER_DECRYPT,
    OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, OSSL_FUNC_ASYM_CIPHER_DUPCTX,
    OSSL_FUNC_ASYM_CIPHER_ENCRYPT, OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,
    OSSL_FUNC_ASYM_CIPHER_FREECTX, OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
    OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, OSSL_FUNC_ASYM_CIPHER_NEWCTX,
    OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, OSSL_LIB_CTX,
    OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_PTR, OSSL_PARAM_OCTET_STRING,
    OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_STRING, OSSL_PKEY_RSA_PAD_MODE_NONE,
    OSSL_PKEY_RSA_PAD_MODE_OAEP, OSSL_PKEY_RSA_PAD_MODE_PKCSV15, PROV_R_BAD_LENGTH,
    PROV_R_BAD_TLS_CLIENT_VERSION, PROV_R_FAILED_TO_DECRYPT, PROV_R_INVALID_KEY,
    PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, PROV_R_OUTPUT_BUFFER_TOO_SMALL, RSA,
    RSA_NO_PADDING,
};
use rustyssl_crypto::rsa as core_rsa;

use super::builtin::libctx_of;
use super::macs::{boxed, context, is_empty, locate, unbox};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::err;
use crate::evp::digest::EVP_MD_get0_name;
use crate::ffi::ffi_callback;
use crate::mem;
use crate::params::{
    OSSL_PARAM_get_int, OSSL_PARAM_get_octet_string, OSSL_PARAM_get_uint,
    OSSL_PARAM_get_utf8_string, OSSL_PARAM_locate, OSSL_PARAM_set_int, OSSL_PARAM_set_octet_ptr,
    OSSL_PARAM_set_uint, OSSL_PARAM_set_utf8_string,
};
use crate::rsa::{Kind, Md, private_random, public_random, raise_all, rsa};
use crate::rsa_ops::{Op, method_op};

/// `OSSL_MAX_NAME_SIZE` and `OSSL_MAX_PROPQUERY_SIZE` (`internal/sizes.h`): the buffers the
/// names and queries are read into.
const MAX_NAME: usize = 50;
const MAX_PROPQUERY: usize = 256;

/// `SSL_MAX_MASTER_KEY_LENGTH`: the premaster secret's length.
const PMS: usize = 48;

/// `padding_item`: the pad modes by name, the correct spelling first, then OpenSSL's old
/// misspelling.
const PADDING_ITEMS: [(c_int, &CStr); 4] = [
    (1, OSSL_PKEY_RSA_PAD_MODE_PKCSV15),
    (3, OSSL_PKEY_RSA_PAD_MODE_NONE),
    (4, OSSL_PKEY_RSA_PAD_MODE_OAEP),
    (4, c"oeap"),
];

/// `PROV_RSA_CTX`.
struct EncCtx {
    libctx: *mut OSSL_LIB_CTX,
    /// The key, with a reference this holds (NULL before an init).
    rsa: *mut RSA,
    pad_mode: c_int,
    operation: c_int,
    oaep_md: Option<Md>,
    mgf1_md: Option<Md>,
    /// The label, at a stable address (`get` hands out a pointer to it).
    label: Option<Box<[u8]>>,
    client_version: c_uint,
    alt_version: c_uint,
    implicit_rejection: c_uint,
}

impl Drop for EncCtx {
    fn drop(&mut self) {
        // SAFETY: the reference this holds, or NULL.
        unsafe { crate::rsa::free(self.rsa) };
    }
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `rsa_newctx`.
unsafe fn ctx<'a>(vctx: *mut c_void) -> Option<&'a mut EncCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { context::<EncCtx>(vctx) }
}

ffi_callback! {
    /// `rsa_newctx`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context.
    pub(crate) unsafe extern "C" fn rsa_enc_newctx(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(EncCtx {
            // SAFETY: the caller's guarantee.
            libctx: unsafe { libctx_of(provctx) },
            rsa: ptr::null_mut(),
            pad_mode: 0,
            operation: 0,
            oaep_md: None,
            mgf1_md: None,
            label: None,
            client_version: 0,
            alt_version: 0,
            implicit_rejection: 0,
        })
    }
}

/// `rsa_init`: the key (a reference), the operation, implicit rejection on and PKCS #1 v1.5,
/// then the parameters. RSA-PSS keys can't encrypt.
///
/// # Safety
/// `vctx` is NULL or a live context; `vrsa` is NULL or live RSA key data; `params` is NULL or
/// an array.
unsafe fn init(
    vctx: *mut c_void,
    vrsa: *mut c_void,
    params: *const OSSL_PARAM,
    operation: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let (Some(c), Some(r)) = (unsafe { ctx(vctx) }, unsafe { rsa(vrsa.cast()) }) else {
        return 0;
    };
    if r.lock().kind == Kind::RsaPss {
        err::raise_with_text(
            ERR_LIB_PROV,
            PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
            "rsa_init",
            &format!("operation: {operation}"),
        );
        return 0;
    }
    // SAFETY: the caller's live key data.
    if !unsafe { crate::rsa::up_ref(vrsa.cast()) } {
        return 0;
    }
    // SAFETY: the reference the context held, or NULL.
    unsafe { crate::rsa::free(c.rsa) };
    c.rsa = vrsa.cast();
    c.operation = operation;
    c.implicit_rejection = 1;
    c.pad_mode = 1;
    // SAFETY: the caller's guarantee.
    unsafe { rsa_enc_set_ctx_params(vctx, params) }
}

ffi_callback! {
    /// `rsa_encrypt_init`.
    ///
    /// # Safety
    /// As for `init`.
    pub(crate) unsafe extern "C" fn rsa_encrypt_init(vctx: *mut c_void, vrsa: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { init(vctx, vrsa, params, EVP_PKEY_OP_ENCRYPT) }
    }
}

ffi_callback! {
    /// `rsa_decrypt_init`.
    ///
    /// # Safety
    /// As for `init`.
    pub(crate) unsafe extern "C" fn rsa_decrypt_init(vctx: *mut c_void, vrsa: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { init(vctx, vrsa, params, EVP_PKEY_OP_DECRYPT) }
    }
}

/// The OAEP digest, SHA-1 (fetched without properties) when none was set.
fn oaep_digest(c: &mut EncCtx, function: &str) -> Option<Md> {
    if c.oaep_md.is_none() {
        // SAFETY: the context's library context; a static name.
        c.oaep_md = unsafe { Md::fetch(c.libctx, c"SHA-1", ptr::null()) };
        if c.oaep_md.is_none() {
            err::raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, function);
            return None;
        }
    }
    c.oaep_md.clone()
}

ffi_callback! {
    /// `rsa_encrypt`: `inlen` octets of `in_` encrypted into `out` (room for `outsize`), or
    /// the size needed for NULL `out`. -1 when the RSA operation fails.
    ///
    /// # Safety
    /// `vctx` is a live context; `outlen` is writable; `out` is NULL or has room for `outsize`
    /// octets; `in_` holds `inlen` octets.
    pub(crate) unsafe extern "C" fn rsa_encrypt(vctx: *mut c_void, out: *mut c_uchar, outlen: *mut usize, outsize: usize, in_: *const c_uchar, inlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "rsa_encrypt";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the context's key.
        let Some(r) = (unsafe { rsa(c.rsa) }) else { return 0 };
        let st = r.snapshot();
        let len = st.key.size();
        if len == 0 {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY, F);
            return 0;
        }
        if out.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { outlen.write(len) };
            return 1;
        }
        if outsize < len {
            err::raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL, F);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(input) = (unsafe { crate::ffi::bytes(in_, inlen) }) else { return 0 };
        // SAFETY: the caller's room for `outsize` octets.
        let output = unsafe { core::slice::from_raw_parts_mut(out, outsize) };
        let mut rng = public_random(c.libctx);
        let outcome = if c.pad_mode == 4 {
            let Some(md) = oaep_digest(c, F) else { return 0 };
            let mgf1 = c.mgf1_md.clone().unwrap_or_else(|| md.clone());
            let mut tbuf = vec![0u8; len];
            let label = c.label.as_deref().unwrap_or_default();
            let (r, raised) = core_rsa::add_oaep(&mut tbuf, input, label, &md, &mgf1, &mut rng);
            raise_all(&raised);
            if r.is_err() {
                return 0;
            }
            // SAFETY: the context's key.
            (unsafe { method_op(c.rsa, Op::PublicEncrypt, &tbuf, output, RSA_NO_PADDING) }, Vec::new())
        } else {
            // SAFETY: as above.
            (unsafe { method_op(c.rsa, Op::PublicEncrypt, input, output, c.pad_mode) }, Vec::new())
        };
        raise_all(&outcome.1);
        match outcome.0 {
            Ok(n) => {
                // SAFETY: the caller's guarantee.
                unsafe { outlen.write(n) };
                1
            }
            Err(()) => -1,
        }
    }
}

ffi_callback! {
    /// `rsa_decrypt`: `inlen` octets of `in_` decrypted into `out` (room for `outsize`), or
    /// the size needed for NULL `out`. The output length is set only on success, and the
    /// result chosen, in constant time.
    ///
    /// # Safety
    /// As for `rsa_encrypt`.
    pub(crate) unsafe extern "C" fn rsa_decrypt(vctx: *mut c_void, out: *mut c_uchar, outlen: *mut usize, outsize: usize, in_: *const c_uchar, inlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "rsa_decrypt";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the context's key.
        let Some(r) = (unsafe { rsa(c.rsa) }) else { return 0 };
        let st = r.snapshot();
        let len = st.key.size();
        let tls = c.pad_mode == 7;
        if tls {
            if out.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { outlen.write(PMS) };
                return 1;
            }
            if outsize < PMS {
                err::raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH, F);
                return 0;
            }
        } else {
            if out.is_null() {
                if len == 0 {
                    err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY, F);
                    return 0;
                }
                // SAFETY: the caller's guarantee.
                unsafe { outlen.write(len) };
                return 1;
            }
            if outsize < len {
                err::raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH, F);
                return 0;
            }
        }
        // SAFETY: the caller's guarantee.
        let Some(input) = (unsafe { crate::ffi::bytes(in_, inlen) }) else { return 0 };
        // SAFETY: the caller's room for `outsize` octets.
        let output = unsafe { core::slice::from_raw_parts_mut(out, outsize) };
        let ret: isize = if c.pad_mode == 4 || tls {
            let mut tbuf = vec![0u8; len];
            // SAFETY: the context's key.
            let r = unsafe { method_op(c.rsa, Op::PrivateDecrypt, input, &mut tbuf, RSA_NO_PADDING) };
            if r != Ok(len) {
                err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_DECRYPT, F);
                return 0;
            }
            if c.pad_mode == 4 {
                let Some(md) = oaep_digest(c, F) else { return 0 };
                let mgf1 = c.mgf1_md.clone().unwrap_or_else(|| md.clone());
                let label = c.label.as_deref().unwrap_or_default();
                let (r, raised) = core_rsa::check_oaep(output, &tbuf, len, label, &md, &mgf1);
                raise_all(&raised);
                r
            } else {
                if c.client_version == 0 {
                    err::raise(ERR_LIB_PROV, PROV_R_BAD_TLS_CLIENT_VERSION, F);
                    return 0;
                }
                let client = c_int::try_from(c.client_version).unwrap_or(0);
                let alt = c_int::try_from(c.alt_version).unwrap_or(0);
                let mut prng = private_random(c.libctx);
                let (r, raised) = core_rsa::check_pkcs1_type2_tls(output, &tbuf, client, alt, &mut prng);
                raise_all(&raised);
                match r {
                    Ok(n) => isize::try_from(n).unwrap_or(-1),
                    Err(()) => -1,
                }
            }
        } else {
            let pad = if c.implicit_rejection == 0 && c.pad_mode == 1 { 8 } else { c.pad_mode };
            // SAFETY: the context's key.
            match unsafe { method_op(c.rsa, Op::PrivateDecrypt, input, output, pad) } {
                Ok(n) => isize::try_from(n).unwrap_or(-1),
                Err(()) => -1,
            }
        };
        // The length, written only for a result (selected without a branch on it).
        let ok = usize::from(ret >= 0);
        // SAFETY: the caller's guarantee.
        let old = unsafe { outlen.read() };
        let mask = ok.wrapping_neg();
        let n = usize::from_ne_bytes(ret.to_ne_bytes());
        // SAFETY: as above.
        unsafe { outlen.write((n & mask) | (old & !mask)) };
        c_int::from(ret >= 0)
    }
}

ffi_callback! {
    /// `rsa_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context the caller gives up.
    pub(crate) unsafe extern "C" fn rsa_enc_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<EncCtx>(vctx) };
    }
}

ffi_callback! {
    /// `rsa_dupctx`: another reference to the key and the digests, a copy of the label.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn rsa_enc_dupctx(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return ptr::null_mut() };
        // SAFETY: the context's key, or NULL.
        if !c.rsa.is_null() && !unsafe { crate::rsa::up_ref(c.rsa) } {
            return ptr::null_mut();
        }
        boxed(EncCtx {
            libctx: c.libctx,
            rsa: c.rsa,
            pad_mode: c.pad_mode,
            operation: c.operation,
            oaep_md: c.oaep_md.clone(),
            mgf1_md: c.mgf1_md.clone(),
            label: c.label.clone(),
            client_version: c.client_version,
            alt_version: c.alt_version,
            implicit_rejection: c.implicit_rejection,
        })
    }
}

/// A digest's name, or "" for none.
fn md_name(md: Option<&Md>) -> *const c_char {
    match md {
        // SAFETY: a live digest.
        Some(m) => unsafe { EVP_MD_get0_name(m.ptr()) },
        None => c"".as_ptr(),
    }
}

ffi_callback! {
    /// `rsa_get_ctx_params`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn rsa_enc_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::RSA_ENC_RSA_GET_CTX_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the caller's array; a static name.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE.as_ptr()) };
        // SAFETY: a parameter of the array, or NULL.
        if let Some(p) = unsafe { p.as_mut() } {
            if p.data_type == OSSL_PARAM_INTEGER as u32 {
                // SAFETY: as above.
                if unsafe { OSSL_PARAM_set_int(p, c.pad_mode) } != 1 {
                    return 0;
                }
            } else if p.data_type == OSSL_PARAM_UTF8_STRING as u32 {
                match PADDING_ITEMS.iter().find(|(id, _)| *id == c.pad_mode) {
                    Some((_, word)) => {
                        // SAFETY: as above; a static string.
                        if unsafe { OSSL_PARAM_set_utf8_string(p, word.as_ptr()) } != 1 {
                            return 0;
                        }
                    }
                    None => err::raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, "rsa_get_ctx_params"),
                }
            } else {
                return 0;
            }
        }
        let mgf1 = c.mgf1_md.as_ref().or(c.oaep_md.as_ref());
        for (name, value) in [
            (OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, md_name(c.oaep_md.as_ref())),
            (OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, md_name(mgf1)),
        ] {
            // SAFETY: the caller's array; a static name.
            let p = unsafe { OSSL_PARAM_locate(params, name.as_ptr()) };
            // SAFETY: a parameter of the array; a string.
            if !p.is_null() && unsafe { OSSL_PARAM_set_utf8_string(p, value) } != 1 {
                return 0;
            }
        }
        // SAFETY: as above.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL.as_ptr()) };
        if !p.is_null() {
            let (lp, ll) = c.label.as_deref().map_or((ptr::null(), 0), |l| (l.as_ptr(), l.len()));
            // SAFETY: a parameter of the array; the label, which stays while the context does.
            if unsafe { OSSL_PARAM_set_octet_ptr(p, lp.cast(), ll) } != 1 {
                return 0;
            }
        }
        for (name, value) in [
            (OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, c.client_version),
            (OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, c.alt_version),
            (OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION, c.implicit_rejection),
        ] {
            // SAFETY: as above.
            let p = unsafe { OSSL_PARAM_locate(params, name.as_ptr()) };
            // SAFETY: a parameter of the array.
            if !p.is_null() && unsafe { OSSL_PARAM_set_uint(p, value) } != 1 {
                return 0;
            }
        }
        1
    }
}

/// `OSSL_PARAM_get_utf8_string` into a buffer of `N` octets (OpenSSL's fixed buffers): the
/// text, or `None` when it isn't a string or doesn't fit.
///
/// # Safety
/// `p` is a parameter.
unsafe fn read_string<const N: usize>(p: &OSSL_PARAM) -> Option<[c_char; N]> {
    let mut buf = [0 as c_char; N];
    let mut s = buf.as_mut_ptr();
    // SAFETY: the parameter; the buffer of N.
    (unsafe { OSSL_PARAM_get_utf8_string(p, &raw mut s, N) } == 1).then_some(buf)
}

ffi_callback! {
    /// `rsa_set_ctx_params`: the OAEP digest (with its properties), the pad mode, the MGF1
    /// digest (with its properties), the label, the TLS versions, and implicit rejection, in
    /// that order.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn rsa_enc_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::RSA_ENC_RSA_SET_CTX_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        let mut mdprops = [0 as c_char; MAX_PROPQUERY];
        // SAFETY: as above, for each locate.
        if let Some(p) = unsafe { locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST) } {
            // SAFETY: a parameter of the array.
            let Some(name) = (unsafe { read_string::<MAX_NAME>(p) }) else { return 0 };
            // SAFETY: as above.
            if let Some(q) = unsafe { locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS) } {
                // SAFETY: a parameter of the array.
                let Some(props) = (unsafe { read_string::<MAX_PROPQUERY>(q) }) else { return 0 };
                mdprops = props;
            }
            // SAFETY: a NUL-terminated buffer.
            let name = unsafe { CStr::from_ptr(name.as_ptr()) };
            // SAFETY: the context's library context; a name and a NUL-terminated buffer.
            c.oaep_md = unsafe { Md::fetch(c.libctx, name, mdprops.as_ptr()) };
            if c.oaep_md.is_none() {
                return 0;
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE) } {
            let mut pad_mode: c_int = 0;
            if p.data_type == OSSL_PARAM_INTEGER as u32 {
                // SAFETY: a parameter of the array; a local.
                if unsafe { OSSL_PARAM_get_int(p, &raw mut pad_mode) } != 1 {
                    return 0;
                }
            } else if p.data_type == OSSL_PARAM_UTF8_STRING as u32 {
                if p.data.is_null() {
                    return 0;
                }
                // SAFETY: a UTF-8 string parameter's data is a string.
                let word = unsafe { CStr::from_ptr(p.data.cast()) };
                // Unknown names leave 0, which is stored.
                if let Some((id, _)) = PADDING_ITEMS.iter().find(|(_, w)| *w == word) {
                    pad_mode = *id;
                }
            } else {
                return 0;
            }
            // PSS is for signatures.
            if pad_mode == 6 {
                return 0;
            }
            if pad_mode == 4 && c.oaep_md.is_none() {
                // SAFETY: the context's library context; a NUL-terminated buffer.
                c.oaep_md = unsafe { Md::fetch(c.libctx, c"SHA1", mdprops.as_ptr()) };
                if c.oaep_md.is_none() {
                    return 0;
                }
            }
            c.pad_mode = pad_mode;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST) } {
            // SAFETY: a parameter of the array.
            let Some(name) = (unsafe { read_string::<MAX_NAME>(p) }) else { return 0 };
            let mut props = None;
            // SAFETY: as above.
            if let Some(q) = unsafe { locate(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS) } {
                // SAFETY: a parameter of the array.
                let Some(v) = (unsafe { read_string::<MAX_PROPQUERY>(q) }) else { return 0 };
                props = Some(v);
            }
            let q = props.as_ref().map_or(ptr::null(), |v| v.as_ptr());
            // SAFETY: a NUL-terminated buffer.
            let name = unsafe { CStr::from_ptr(name.as_ptr()) };
            // SAFETY: the context's library context; a name and a query.
            c.mgf1_md = unsafe { Md::fetch(c.libctx, name, q) };
            if c.mgf1_md.is_none() {
                return 0;
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL) } {
            let mut data: *mut c_void = ptr::null_mut();
            let mut n: usize = 0;
            // SAFETY: a parameter of the array; a place for a new allocation and its length.
            if unsafe { OSSL_PARAM_get_octet_string(p, &raw mut data, 0, &raw mut n) } != 1 {
                return 0;
            }
            // SAFETY: the allocation just made holds `n` octets.
            let label = unsafe { crate::ffi::bytes(data.cast::<u8>(), n) }.unwrap_or_default().to_vec();
            // SAFETY: the allocation just made, freed once.
            unsafe { mem::release(data) };
            c.label = Some(label.into_boxed_slice());
        }
        for (name, slot) in [
            (OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, &mut c.client_version),
            (OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, &mut c.alt_version),
            (OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION, &mut c.implicit_rejection),
        ] {
            // SAFETY: as above.
            if let Some(p) = unsafe { locate(params, name) } {
                let mut v: c_uint = 0;
                // SAFETY: a parameter of the array; a local.
                if unsafe { OSSL_PARAM_get_uint(p, &raw mut v) } != 1 {
                    return 0;
                }
                *slot = v;
            }
        }
        1
    }
}

/// `known_gettable_ctx_params`.
static GETTABLE: Params<9> = Params([
    defn(
        OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
        OSSL_PARAM_UTF8_STRING,
        0,
    ),
    defn(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, OSSL_PARAM_UTF8_STRING, 0),
    defn(
        OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
        OSSL_PARAM_INTEGER,
        size_of::<c_int>(),
    ),
    defn(
        OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
        OSSL_PARAM_UTF8_STRING,
        0,
    ),
    defn(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, OSSL_PARAM_OCTET_PTR, 0),
    defn(
        OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION,
        OSSL_PARAM_UNSIGNED_INTEGER,
        4,
    ),
    defn(
        OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION,
        OSSL_PARAM_UNSIGNED_INTEGER,
        4,
    ),
    defn(
        OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION,
        OSSL_PARAM_UNSIGNED_INTEGER,
        4,
    ),
    PARAM_END,
]);

/// `known_settable_ctx_params`.
static SETTABLE: Params<11> = Params([
    defn(
        OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
        OSSL_PARAM_UTF8_STRING,
        0,
    ),
    defn(
        OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS,
        OSSL_PARAM_UTF8_STRING,
        0,
    ),
    defn(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, OSSL_PARAM_UTF8_STRING, 0),
    defn(
        OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
        OSSL_PARAM_INTEGER,
        size_of::<c_int>(),
    ),
    defn(
        OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
        OSSL_PARAM_UTF8_STRING,
        0,
    ),
    defn(
        OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS,
        OSSL_PARAM_UTF8_STRING,
        0,
    ),
    defn(
        OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    defn(
        OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION,
        OSSL_PARAM_UNSIGNED_INTEGER,
        4,
    ),
    defn(
        OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION,
        OSSL_PARAM_UNSIGNED_INTEGER,
        4,
    ),
    defn(
        OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION,
        OSSL_PARAM_UNSIGNED_INTEGER,
        4,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `rsa_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn rsa_enc_gettable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `rsa_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn rsa_enc_settable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE.0.as_ptr()
    }
}

type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type InitFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
type CryptFn = unsafe extern "C" fn(
    *mut c_void,
    *mut c_uchar,
    *mut usize,
    usize,
    *const c_uchar,
    usize,
) -> c_int;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type ParamsFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

/// `ossl_rsa_asym_cipher_functions`.
pub(crate) static RSA_ASYM_CIPHER: Dispatch<12> = Dispatch([
    entry!(OSSL_FUNC_ASYM_CIPHER_NEWCTX, rsa_enc_newctx, NewCtxFn),
    entry!(OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, rsa_encrypt_init, InitFn),
    entry!(OSSL_FUNC_ASYM_CIPHER_ENCRYPT, rsa_encrypt, CryptFn),
    entry!(OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, rsa_decrypt_init, InitFn),
    entry!(OSSL_FUNC_ASYM_CIPHER_DECRYPT, rsa_decrypt, CryptFn),
    entry!(OSSL_FUNC_ASYM_CIPHER_FREECTX, rsa_enc_freectx, FreeCtxFn),
    entry!(OSSL_FUNC_ASYM_CIPHER_DUPCTX, rsa_enc_dupctx, DupCtxFn),
    entry!(
        OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
        rsa_enc_get_ctx_params,
        GetParamsFn
    ),
    entry!(
        OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
        rsa_enc_gettable_ctx_params,
        ParamsFn
    ),
    entry!(
        OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
        rsa_enc_set_ctx_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
        rsa_enc_settable_ctx_params,
        ParamsFn
    ),
    END,
]);
