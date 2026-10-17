//! The default and base providers' decoders (`decoders.inc`; `decode_pem2der.c`,
//! `decode_spki2typespki.c`, `decode_epki2pki.c`): the key decoders (`der2key`, with
//! placeholders for those still to come in `pending_keys`) and the structural ones a key's
//! decoding goes through — PEM to DER (`pem2der`, which also decrypts a traditional PEM's
//! DEK-Info and names what each PEM type holds), SubjectPublicKeyInfo to its key type's
//! (`spki2typespki`), and EncryptedPrivateKeyInfo to PrivateKeyInfo (`epki2pki`, whose
//! decryption comes with step 4.7d).
//!
//! As OpenSSL's, a decoder that doesn't recognize its input succeeds without passing anything
//! on, so the walk tries the next one.

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PROV, EVP_CIPHER_INFO, NID_X9_62_id_ecPublicKey, NID_sm2, OSSL_ALGORITHM,
    OSSL_CALLBACK, OSSL_CORE_BIO, OSSL_DECODER_PARAM_PROPERTIES, OSSL_FUNC_DECODER_DECODE,
    OSSL_FUNC_DECODER_FREECTX, OSSL_FUNC_DECODER_NEWCTX, OSSL_FUNC_DECODER_SET_CTX_PARAMS,
    OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_OBJECT_CERT, OSSL_OBJECT_CRL, OSSL_OBJECT_PARAM_DATA,
    OSSL_OBJECT_PARAM_DATA_STRUCTURE, OSSL_OBJECT_PARAM_DATA_TYPE, OSSL_OBJECT_PARAM_INPUT_TYPE,
    OSSL_OBJECT_PARAM_TYPE, OSSL_OBJECT_PKEY, OSSL_PARAM, OSSL_PARAM_UTF8_STRING,
    OSSL_PASSPHRASE_CALLBACK, PEM_STRING_DHPARAMS, PEM_STRING_DHXPARAMS, PEM_STRING_DSA,
    PEM_STRING_DSA_PUBLIC, PEM_STRING_DSAPARAMS, PEM_STRING_ECPARAMETERS, PEM_STRING_ECPRIVATEKEY,
    PEM_STRING_PKCS8, PEM_STRING_PKCS8INF, PEM_STRING_PUBLIC, PEM_STRING_RSA,
    PEM_STRING_RSA_PUBLIC, PEM_STRING_SM2PARAMETERS, PEM_STRING_SM2PRIVATEKEY, PEM_STRING_X509,
    PEM_STRING_X509_CRL, PEM_STRING_X509_OLD, PEM_STRING_X509_TRUSTED,
    PROV_R_UNABLE_TO_GET_PASSPHRASE, V_ASN1_OBJECT, V_ASN1_SEQUENCE,
};

use super::builtin::libctx_of;
use super::tables::{Algorithms, Dispatch, END, PARAM_END, Params, defn, entry};
use super::{der2key, pending_keys};
use crate::decoder::ctx::bio_new_from_core_bio;
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::ffi::ffi_callback;
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_utf8_string, OSSL_PARAM_get_utf8_string, OSSL_PARAM_locate_const,
};

/// `OSSL_MAX_PROPQUERY_SIZE`, `OSSL_MAX_CODEC_STRUCT_SIZE`, and `OSSL_MAX_NAME_SIZE`
/// (`internal/sizes.h`).
const MAX_PROPQUERY: usize = 256;
const MAX_CODEC_STRUCT: usize = 32;
const MAX_NAME: usize = 50;
/// `MAX_NAME` as `OBJ_obj2txt` takes it.
const NAME_LEN: c_int = 50;

/// A structural decoder's context: the provider's context, the data structure asked for
/// (`pem2der` only), and the properties to fetch with, each in OpenSSL's fixed buffers.
struct DecCtx {
    #[allow(
        dead_code,
        reason = "the key decoders (4.7b2) and decryption (4.7d) fetch with it"
    )]
    provctx: *mut c_void,
    data_structure: [c_char; MAX_CODEC_STRUCT],
    propq: [c_char; MAX_PROPQUERY],
}

#[allow(
    dead_code,
    reason = "the key decoders (4.7b2) and decryption (4.7d) fetch with these"
)]
impl DecCtx {
    /// The library context of the provider's context.
    fn libctx(&self) -> *mut rustyssl_abi::OSSL_LIB_CTX {
        // SAFETY: the provider's context, live while the provider is.
        unsafe { libctx_of(self.provctx) }
    }

    /// The properties set, as a C string.
    fn propq(&self) -> *const c_char {
        self.propq.as_ptr()
    }

    /// The data structure set (empty for none).
    fn data_structure(&self) -> &[u8] {
        // SAFETY: NUL-terminated within the buffer (zeroed, then written by the parameter
        // getter with its terminator).
        unsafe { CStr::from_ptr(self.data_structure.as_ptr()) }.to_bytes()
    }
}

ffi_callback! {
    /// `pem2der_newctx` (and the others'): a zeroed context.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn dec_newctx(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        Box::into_raw(Box::new(DecCtx {
            provctx,
            data_structure: [0; MAX_CODEC_STRUCT],
            propq: [0; MAX_PROPQUERY],
        }))
        .cast()
    }
}

ffi_callback! {
    /// `pem2der_freectx` (and the others').
    ///
    /// # Safety
    /// `vctx` is NULL or a context from `dec_newctx` the caller gives up.
    pub(crate) unsafe extern "C" fn dec_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        if !vctx.is_null() {
            // SAFETY: the caller's guarantee.
            drop(unsafe { Box::from_raw(vctx.cast::<DecCtx>()) });
        }
    }
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `dec_newctx`.
unsafe fn dctx<'a>(vctx: *mut c_void) -> Option<&'a mut DecCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { vctx.cast::<DecCtx>().as_mut() }
}

/// Reads a UTF-8 parameter into a fixed buffer (`OSSL_PARAM_get_utf8_string` with its size);
/// true if there's none.
///
/// # Safety
/// `params` is NULL or an array.
pub(super) unsafe fn read_into<const N: usize>(
    params: *const OSSL_PARAM,
    key: &CStr,
    buf: &mut [c_char; N],
) -> bool {
    // SAFETY: the caller's array; a static name.
    let p = unsafe { OSSL_PARAM_locate_const(params, key.as_ptr()) };
    if p.is_null() {
        return true;
    }
    let mut s = buf.as_mut_ptr();
    // SAFETY: a parameter of the array; the buffer of N.
    unsafe { OSSL_PARAM_get_utf8_string(p, &raw mut s, N) != 0 }
}

/// The settable parameters of `pem2der`.
static PEM2DER_SETTABLE: Params<3> = Params([
    defn(OSSL_DECODER_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_OBJECT_PARAM_DATA_STRUCTURE, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

/// The settable parameters of `spki2typespki` and `epki2pki`.
static PROPS_SETTABLE: Params<2> = Params([
    defn(OSSL_DECODER_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `pem2der_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn pem2der_settable_ctx_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        PEM2DER_SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `spki2typespki_settable_ctx_params` and `epki2pki_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn props_settable_ctx_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        PROPS_SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `pem2der_set_ctx_params`: the properties and the data structure.
    ///
    /// # Safety
    /// `vctx` is a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn pem2der_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { dctx(vctx) }) else { return 0 };
        // SAFETY: as above.
        if !unsafe { read_into(params, OSSL_DECODER_PARAM_PROPERTIES, &mut c.propq) } {
            return 0;
        }
        // SAFETY: as above.
        c_int::from(unsafe { read_into(params, OSSL_OBJECT_PARAM_DATA_STRUCTURE, &mut c.data_structure) })
    }
}

ffi_callback! {
    /// `spki2typespki_set_ctx_params` and `epki2pki_set_ctx_params`: the properties.
    ///
    /// # Safety
    /// `vctx` is a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn props_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { dctx(vctx) }) else { return 0 };
        // SAFETY: as above.
        c_int::from(unsafe { read_into(params, OSSL_DECODER_PARAM_PROPERTIES, &mut c.propq) })
    }
}

/// Passes on decoded data (`OSSL_OBJECT_PARAM_*`): its type and structure when given, input
/// type, octets, and object type.
///
/// # Safety
/// The strings are NULL or strings; `data` holds `len` octets; `data_cb` takes `data_cbarg`.
#[allow(clippy::too_many_arguments)]
unsafe fn pass_on(
    data_type: *const c_char,
    input_type: *const c_char,
    data_structure: *const c_char,
    data: *const c_uchar,
    len: usize,
    objtype: c_int,
    data_cb: OSSL_CALLBACK,
    data_cbarg: *mut c_void,
) -> c_int {
    let mut objtype = objtype;
    let mut params: Vec<OSSL_PARAM> = Vec::with_capacity(6);
    for (key, v) in [
        (OSSL_OBJECT_PARAM_DATA_TYPE, data_type),
        (OSSL_OBJECT_PARAM_INPUT_TYPE, input_type),
        (OSSL_OBJECT_PARAM_DATA_STRUCTURE, data_structure),
    ] {
        if !v.is_null() {
            // SAFETY: a static name; the caller's string, read during the call.
            params.push(unsafe { OSSL_PARAM_construct_utf8_string(key.as_ptr(), v.cast_mut(), 0) });
        }
    }
    // SAFETY: a static name; the caller's octets, read during the call.
    params.push(unsafe {
        OSSL_PARAM_construct_octet_string(
            OSSL_OBJECT_PARAM_DATA.as_ptr(),
            data.cast_mut().cast(),
            len,
        )
    });
    // SAFETY: a static name; a local that outlives the call.
    params.push(unsafe {
        OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE.as_ptr(), &raw mut objtype)
    });
    // SAFETY: no preconditions.
    params.push(unsafe { OSSL_PARAM_construct_end() });
    let Some(cb) = data_cb else { return 0 };
    // SAFETY: the decoding's callback with the parameters and its argument.
    unsafe { cb(params.as_ptr(), data_cbarg) }
}

/// `ossl_x509_algor_is_sm2`: whether the AlgorithmIdentifier's parameters name SM2 (its OID, or
/// ECParameters of its curve).
///
/// # Safety
/// `palg` is a live AlgorithmIdentifier.
unsafe fn algor_is_sm2(palg: *const rustyssl_abi::X509_ALGOR) -> bool {
    let (mut ptype, mut pval) = (0, ptr::null());
    // SAFETY: the caller's AlgorithmIdentifier; locals.
    unsafe {
        crate::x509::algor::X509_ALGOR_get0(ptr::null_mut(), &raw mut ptype, &raw mut pval, palg)
    };
    if ptype == V_ASN1_OBJECT {
        // SAFETY: an OBJECT parameter is an object.
        return unsafe { crate::objects::OBJ_obj2nid(pval.cast()) } == NID_sm2;
    }
    if ptype == V_ASN1_SEQUENCE {
        // SAFETY: a SEQUENCE parameter is an `ASN1_STRING`.
        let (mut der, len) = unsafe { crate::x509::pubkey::sequence_octets(pval) };
        // SAFETY: its octets.
        let group =
            unsafe { crate::ec::asn1::d2i_ECPKParameters(ptr::null_mut(), &raw mut der, len) };
        let ret = !group.is_null()
            // SAFETY: the group decoded.
            && unsafe { crate::ec::group::EC_GROUP_get_curve_name(group) } == NID_sm2;
        // SAFETY: decoded above, or NULL.
        unsafe { crate::ec::group::EC_GROUP_free(group) };
        return ret;
    }
    false
}

/// `ossl_spki2typespki_der_decode`: a SubjectPublicKeyInfo passed on as its key type's (SM2 for
/// an EC key on SM2's curve, else its algorithm's OID or name); a non-SPKI succeeds with nothing.
///
/// # Safety
/// `der` holds `len` octets; the callbacks take their arguments.
unsafe fn spki2typespki_der_decode(
    der: &[u8],
    data_cb: OSSL_CALLBACK,
    data_cbarg: *mut c_void,
) -> c_int {
    let mut p = der.as_ptr();
    let Ok(len) = c_long::try_from(der.len()) else {
        return 1;
    };
    // SAFETY: the octets.
    let xpub = unsafe { crate::x509::pubkey::d2i_internal(&raw mut p, len) };
    if xpub.is_null() {
        return 1;
    }
    let mut algor = ptr::null_mut();
    // SAFETY: the structure decoded; a local.
    let got = unsafe {
        crate::x509::pubkey::X509_PUBKEY_get0_param(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut algor,
            xpub,
        )
    };
    let mut dataname = [0 as c_char; MAX_NAME];
    let named = got != 0 && {
        // SAFETY: its AlgorithmIdentifier.
        let oid = unsafe { (*algor).algorithm };
        // SAFETY: its object; its AlgorithmIdentifier.
        if unsafe { crate::objects::OBJ_obj2nid(oid) } == NID_X9_62_id_ecPublicKey
            // SAFETY: as above.
            && unsafe { algor_is_sm2(algor) }
        {
            for (d, s) in dataname.iter_mut().zip(c"SM2".to_bytes_with_nul()) {
                *d = c_char::from_ne_bytes([*s]);
            }
            true
        } else {
            // SAFETY: the buffer of MAX_NAME; the object.
            (unsafe { crate::objects::OBJ_obj2txt(dataname.as_mut_ptr(), NAME_LEN, oid, 0) }) > 0
        }
    };
    // SAFETY: decoded above.
    unsafe { crate::x509::pubkey::free_internal(xpub) };
    if !named {
        return 0;
    }
    // SAFETY: the name and the static strings; the caller's octets and callback.
    unsafe {
        pass_on(
            dataname.as_ptr(),
            c"DER".as_ptr(),
            c"SubjectPublicKeyInfo".as_ptr(),
            der.as_ptr(),
            der.len(),
            OSSL_OBJECT_PKEY,
            data_cb,
            data_cbarg,
        )
    }
}

/// `ossl_epki2pki_der_decode`: an EncryptedPrivateKeyInfo decrypted with the passphrase (step
/// 4.7d), then a PrivateKeyInfo passed on as its key type's; anything else succeeds with
/// nothing.
///
/// # Safety
/// `der` holds its octets; the callbacks take their arguments.
unsafe fn epki2pki_der_decode(
    der: &[u8],
    data_cb: OSSL_CALLBACK,
    data_cbarg: *mut c_void,
    pw_cb: OSSL_PASSPHRASE_CALLBACK,
    pw_cbarg: *mut c_void,
) -> c_int {
    let Ok(len) = c_long::try_from(der.len()) else {
        return 1;
    };
    let mut ok = 1;
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    let mut pder = der.as_ptr();
    // SAFETY: the octets.
    let p8 = unsafe { crate::x509::sig::d2i_X509_SIG(ptr::null_mut(), &raw mut pder, len) };
    if p8.is_null() {
        // SAFETY: the mark set above.
        unsafe { ERR_pop_to_mark() };
    } else {
        // SAFETY: as above.
        unsafe { ERR_clear_last_mark() };
        let mut pbuf = [0 as c_char; 1024];
        let mut plen = 0usize;
        let got = match pw_cb {
            Some(cb) => {
                // SAFETY: the decoding's passphrase callback with room for 1024 octets.
                (unsafe {
                    cb(
                        pbuf.as_mut_ptr(),
                        pbuf.len(),
                        &raw mut plen,
                        ptr::null(),
                        pw_cbarg,
                    )
                }) != 0
            }
            None => false,
        };
        if got {
            crate::stub::unimplemented(
                "decrypting an EncryptedPrivateKeyInfo (PKCS12_pbe_crypt_ex, step 4.7d)",
            );
        }
        err::raise(
            ERR_LIB_PROV,
            PROV_R_UNABLE_TO_GET_PASSPHRASE,
            "ossl_epki2pki_der_decode",
        );
        ok = 0;
        // SAFETY: decoded above.
        unsafe { crate::x509::sig::X509_SIG_free(p8) };
    }
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    let mut pder = der.as_ptr();
    // SAFETY: the octets.
    let p8inf =
        unsafe { crate::x509::p8::d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), &raw mut pder, len) };
    // SAFETY: the mark set above.
    unsafe { ERR_pop_to_mark() };
    let mut alg = ptr::null();
    if !p8inf.is_null()
        // SAFETY: decoded; a local.
        && unsafe {
            crate::x509::p8::PKCS8_pkey_get0(
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut alg,
                p8inf,
            )
        } != 0
    {
        let mut keytype = [0 as c_char; MAX_NAME];
        // SAFETY: the PrivateKeyInfo's AlgorithmIdentifier.
        let obj = unsafe { (*alg).algorithm };
        // SAFETY: the buffer of MAX_NAME; its algorithm's object.
        unsafe { crate::objects::OBJ_obj2txt(keytype.as_mut_ptr(), NAME_LEN, obj, 0) };
        // SAFETY: the type and static strings; the caller's octets and callback.
        ok = unsafe {
            pass_on(
                keytype.as_ptr(),
                c"DER".as_ptr(),
                c"PrivateKeyInfo".as_ptr(),
                der.as_ptr(),
                der.len(),
                OSSL_OBJECT_PKEY,
                data_cb,
                data_cbarg,
            )
        };
    }
    // SAFETY: decoded above, or NULL.
    unsafe { crate::x509::p8::PKCS8_PRIV_KEY_INFO_free(p8inf) };
    ok
}

/// `ossl_read_der` over a core BIO: one element's octets, or `None`.
///
/// # Safety
/// `cin` is a live core BIO.
pub(super) unsafe fn read_der(cin: *mut OSSL_CORE_BIO) -> Option<Vec<u8>> {
    // SAFETY: the caller's guarantee.
    let input = unsafe { bio_new_from_core_bio(cin) };
    if input.is_null() {
        return None;
    }
    // SAFETY: the new BIO.
    let out = unsafe { crate::asn1::tpl::io::read_der(input) };
    // SAFETY: made above.
    unsafe { crate::bio::BIO_free(input) };
    out
}

ffi_callback! {
    /// `spki2typespki_decode`.
    ///
    /// # Safety
    /// As for a decoder's `decode`.
    pub(crate) unsafe extern "C" fn spki2typespki_decode(_vctx: *mut c_void, cin: *mut OSSL_CORE_BIO, _selection: c_int, data_cb: OSSL_CALLBACK, data_cbarg: *mut c_void, _pw_cb: OSSL_PASSPHRASE_CALLBACK, _pw_cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(der) = (unsafe { read_der(cin) }) else { return 1 };
        // SAFETY: as above.
        unsafe { spki2typespki_der_decode(&der, data_cb, data_cbarg) }
    }
}

ffi_callback! {
    /// `epki2pki_decode`.
    ///
    /// # Safety
    /// As for a decoder's `decode`.
    pub(crate) unsafe extern "C" fn epki2pki_decode(_vctx: *mut c_void, cin: *mut OSSL_CORE_BIO, _selection: c_int, data_cb: OSSL_CALLBACK, data_cbarg: *mut c_void, pw_cb: OSSL_PASSPHRASE_CALLBACK, pw_cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(der) = (unsafe { read_der(cin) }) else { return 1 };
        // SAFETY: as above.
        unsafe { epki2pki_der_decode(&der, data_cb, data_cbarg, pw_cb, pw_cbarg) }
    }
}

/// `pem2der_pass_data_st`.
struct PassData {
    cb: OSSL_PASSPHRASE_CALLBACK,
    cbarg: *mut c_void,
}

/// `pem2der_pass_helper`: a `pem_password_cb` over the decoding's passphrase callback.
///
/// # Safety
/// `buf` has room for `num` octets; `data` is a live `PassData`.
unsafe extern "C" fn pass_helper(
    buf: *mut c_char,
    num: c_int,
    _w: c_int,
    data: *mut c_void,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(pd) = (unsafe { data.cast::<PassData>().as_ref() }) else {
        return -1;
    };
    let Some(cb) = pd.cb else { return -1 };
    let mut plen = 0usize;
    let Ok(n) = usize::try_from(num) else {
        return -1;
    };
    // SAFETY: the decoding's callback with the caller's room.
    if unsafe { cb(buf, n, &raw mut plen, ptr::null(), pd.cbarg) } == 0 {
        return -1;
    }
    c_int::try_from(plen).unwrap_or(-1)
}

/// `pem_name_map`: what each PEM type holds — its object type, data type, and data structure.
const PEM_NAMES: [(&CStr, c_int, Option<&CStr>, Option<&CStr>); 18] = [
    (
        PEM_STRING_PKCS8,
        OSSL_OBJECT_PKEY,
        None,
        Some(c"EncryptedPrivateKeyInfo"),
    ),
    (
        PEM_STRING_PKCS8INF,
        OSSL_OBJECT_PKEY,
        None,
        Some(c"PrivateKeyInfo"),
    ),
    (
        PEM_STRING_PUBLIC,
        OSSL_OBJECT_PKEY,
        None,
        Some(c"SubjectPublicKeyInfo"),
    ),
    (
        PEM_STRING_DHPARAMS,
        OSSL_OBJECT_PKEY,
        Some(c"DH"),
        Some(c"type-specific"),
    ),
    (
        PEM_STRING_DHXPARAMS,
        OSSL_OBJECT_PKEY,
        Some(c"X9.42 DH"),
        Some(c"type-specific"),
    ),
    (
        PEM_STRING_DSA,
        OSSL_OBJECT_PKEY,
        Some(c"DSA"),
        Some(c"type-specific"),
    ),
    (
        PEM_STRING_DSA_PUBLIC,
        OSSL_OBJECT_PKEY,
        Some(c"DSA"),
        Some(c"type-specific"),
    ),
    (
        PEM_STRING_DSAPARAMS,
        OSSL_OBJECT_PKEY,
        Some(c"DSA"),
        Some(c"type-specific"),
    ),
    (
        PEM_STRING_ECPRIVATEKEY,
        OSSL_OBJECT_PKEY,
        Some(c"EC"),
        Some(c"type-specific"),
    ),
    (
        PEM_STRING_ECPARAMETERS,
        OSSL_OBJECT_PKEY,
        Some(c"EC"),
        Some(c"type-specific"),
    ),
    (
        PEM_STRING_SM2PRIVATEKEY,
        OSSL_OBJECT_PKEY,
        Some(c"SM2"),
        Some(c"type-specific"),
    ),
    (
        PEM_STRING_SM2PARAMETERS,
        OSSL_OBJECT_PKEY,
        Some(c"SM2"),
        Some(c"type-specific"),
    ),
    (
        PEM_STRING_RSA,
        OSSL_OBJECT_PKEY,
        Some(c"RSA"),
        Some(c"type-specific"),
    ),
    (
        PEM_STRING_RSA_PUBLIC,
        OSSL_OBJECT_PKEY,
        Some(c"RSA"),
        Some(c"type-specific"),
    ),
    (
        PEM_STRING_X509,
        OSSL_OBJECT_CERT,
        None,
        Some(c"Certificate"),
    ),
    (
        PEM_STRING_X509_TRUSTED,
        OSSL_OBJECT_CERT,
        None,
        Some(c"Certificate"),
    ),
    (
        PEM_STRING_X509_OLD,
        OSSL_OBJECT_CERT,
        None,
        Some(c"Certificate"),
    ),
    (
        PEM_STRING_X509_CRL,
        OSSL_OBJECT_CRL,
        None,
        Some(c"CertificateList"),
    ),
];

/// The last PKCS#8 and SPKI entries of `PEM_NAMES` (`PKCS8_LAST_IDX`, `SPKI_LAST_IDX`).
const PKCS8_LAST_IDX: usize = 1;
const SPKI_LAST_IDX: usize = 2;

/// An optional static name as a pointer.
fn name_ptr(s: Option<&CStr>) -> *const c_char {
    s.map_or(ptr::null(), CStr::as_ptr)
}

ffi_callback! {
    /// `pem2der_decode`: a PEM block read, decrypted if its header says so, then passed on as
    /// DER with what its type holds (or to `epki2pki`'s or `spki2typespki`'s work for PKCS#8
    /// and public keys when they're asked for); a block that doesn't read succeeds with nothing.
    ///
    /// # Safety
    /// As for a decoder's `decode`.
    pub(crate) unsafe extern "C" fn pem2der_decode(vctx: *mut c_void, cin: *mut OSSL_CORE_BIO, selection: c_int, data_cb: OSSL_CALLBACK, data_cbarg: *mut c_void, pw_cb: OSSL_PASSPHRASE_CALLBACK, pw_cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { dctx(vctx) }) else { return 0 };
        // SAFETY: as above.
        let input = unsafe { bio_new_from_core_bio(cin) };
        if input.is_null() {
            return 1;
        }
        let (mut pem_name, mut pem_header, mut der, mut der_len) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 0 as c_long);
        // SAFETY: the BIO; locals.
        let read = unsafe { crate::pem::PEM_read_bio(input, &raw mut pem_name, &raw mut pem_header, &raw mut der, &raw mut der_len) } > 0;
        // SAFETY: made above.
        unsafe { crate::bio::BIO_free(input) };
        if !read {
            return 1;
        }
        let free_all = |ok: c_int| {
            // SAFETY: the reading's allocations, freed once.
            unsafe { crate::mem::release(pem_name.cast()) };
            // SAFETY: as above.
            unsafe { crate::mem::release(pem_header.cast()) };
            // SAFETY: as above.
            unsafe { crate::mem::release(der.cast()) };
            ok
        };
        // SAFETY: the header, a string.
        if unsafe { CStr::from_ptr(pem_header) }.to_bytes().len() > 10 {
            let mut cipher: EVP_CIPHER_INFO = EVP_CIPHER_INFO { cipher: ptr::null(), iv: [0; 16] };
            let mut pass = PassData { cb: pw_cb, cbarg: pw_cbarg };
            // SAFETY: the header; a local.
            let ok = unsafe { crate::pem_cipher::PEM_get_EVP_CIPHER_INFO(pem_header, &raw mut cipher) } != 0
                // SAFETY: the cipher; the data and its length; the helper over the passphrase.
                && unsafe { crate::pem_cipher::PEM_do_header(&raw mut cipher, der, &raw mut der_len, Some(pass_helper), (&raw mut pass).cast()) } != 0;
            if !ok {
                return free_all(0);
            }
        }
        // SAFETY: the name, a string.
        let name = unsafe { CStr::from_ptr(pem_name) };
        let Some((i, &(_, objtype, data_type, data_structure))) = PEM_NAMES.iter().enumerate().find(|(_, e)| e.0 == name) else {
            return free_all(1);
        };
        let asked = c.data_structure();
        let len = usize::try_from(der_len).unwrap_or(0);
        // SAFETY: the decoded octets.
        let bytes = unsafe { crate::ffi::bytes(der, len) }.unwrap_or_default();
        let ok = if i <= PKCS8_LAST_IDX
            && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0
                || asked.eq_ignore_ascii_case(b"EncryptedPrivateKeyInfo")
                || asked.eq_ignore_ascii_case(b"PrivateKeyInfo"))
        {
            // SAFETY: the octets; the caller's callbacks.
            unsafe { epki2pki_der_decode(bytes, data_cb, data_cbarg, pw_cb, pw_cbarg) }
        } else if i <= SPKI_LAST_IDX
            && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY != 0 || asked.eq_ignore_ascii_case(b"SubjectPublicKeyInfo"))
        {
            // SAFETY: as above.
            unsafe { spki2typespki_der_decode(bytes, data_cb, data_cbarg) }
        } else {
            // SAFETY: the static strings; the octets; the caller's callback.
            unsafe {
                pass_on(name_ptr(data_type), ptr::null(), name_ptr(data_structure), der, len, objtype, data_cb, data_cbarg)
            }
        };
        free_all(ok)
    }
}

type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type DecodeFn = unsafe extern "C" fn(
    *mut c_void,
    *mut OSSL_CORE_BIO,
    c_int,
    OSSL_CALLBACK,
    *mut c_void,
    OSSL_PASSPHRASE_CALLBACK,
    *mut c_void,
) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;

/// `ossl_pem_to_der_decoder_functions`.
static PEM_TO_DER: Dispatch<6> = Dispatch([
    entry!(OSSL_FUNC_DECODER_NEWCTX, dec_newctx, NewCtxFn),
    entry!(OSSL_FUNC_DECODER_FREECTX, dec_freectx, FreeCtxFn),
    entry!(OSSL_FUNC_DECODER_DECODE, pem2der_decode, DecodeFn),
    entry!(
        OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
        pem2der_settable_ctx_params,
        ListFn
    ),
    entry!(
        OSSL_FUNC_DECODER_SET_CTX_PARAMS,
        pem2der_set_ctx_params,
        SetParamsFn
    ),
    END,
]);

/// `ossl_SubjectPublicKeyInfo_der_to_der_decoder_functions`.
static SPKI_TO_DER: Dispatch<6> = Dispatch([
    entry!(OSSL_FUNC_DECODER_NEWCTX, dec_newctx, NewCtxFn),
    entry!(OSSL_FUNC_DECODER_FREECTX, dec_freectx, FreeCtxFn),
    entry!(OSSL_FUNC_DECODER_DECODE, spki2typespki_decode, DecodeFn),
    entry!(
        OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
        props_settable_ctx_params,
        ListFn
    ),
    entry!(
        OSSL_FUNC_DECODER_SET_CTX_PARAMS,
        props_set_ctx_params,
        SetParamsFn
    ),
    END,
]);

/// `ossl_EncryptedPrivateKeyInfo_der_to_der_decoder_functions`.
static EPKI_TO_DER: Dispatch<6> = Dispatch([
    entry!(OSSL_FUNC_DECODER_NEWCTX, dec_newctx, NewCtxFn),
    entry!(OSSL_FUNC_DECODER_FREECTX, dec_freectx, FreeCtxFn),
    entry!(OSSL_FUNC_DECODER_DECODE, epki2pki_decode, DecodeFn),
    entry!(
        OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
        props_settable_ctx_params,
        ListFn
    ),
    entry!(
        OSSL_FUNC_DECODER_SET_CTX_PARAMS,
        props_set_ctx_params,
        SetParamsFn
    ),
    END,
]);

/// A decoder algorithm (`DECODER`/`DECODER_w_structure` in `decoders.inc`).
const fn decoder<const N: usize>(
    names: &'static CStr,
    props: &'static CStr,
    table: &'static Dispatch<N>,
) -> OSSL_ALGORITHM {
    OSSL_ALGORITHM {
        algorithm_names: names.as_ptr(),
        property_definition: props.as_ptr(),
        implementation: table.0.as_ptr(),
        algorithm_description: ptr::null(),
    }
}

/// The default provider's decoders, in `decoders.inc`'s order (the structural ones come last);
/// the MSBLOB and PVK ones are placeholders (`pending_keys`).
static DEFAULT_DECODERS: Algorithms<77> = Algorithms([
    decoder(
        c"DH",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_DH,
    ),
    decoder(
        c"DH",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_DH,
    ),
    decoder(
        c"DH",
        c"provider=default,fips=yes,input=der,structure=type-specific",
        &der2key::TS_DH,
    ),
    decoder(
        c"DH",
        c"provider=default,fips=yes,input=der,structure=dh",
        &der2key::DH_DH,
    ),
    decoder(
        c"DHX",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_DHX,
    ),
    decoder(
        c"DHX",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_DHX,
    ),
    decoder(
        c"DHX",
        c"provider=default,fips=yes,input=der,structure=type-specific",
        &der2key::TS_DHX,
    ),
    decoder(
        c"DHX",
        c"provider=default,fips=yes,input=der,structure=dhx",
        &der2key::DHX_DHX,
    ),
    decoder(
        c"DSA",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_DSA,
    ),
    decoder(
        c"DSA",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_DSA,
    ),
    decoder(
        c"DSA",
        c"provider=default,fips=yes,input=der,structure=type-specific",
        &der2key::TS_DSA,
    ),
    decoder(
        c"DSA",
        c"provider=default,fips=yes,input=der,structure=dsa",
        &der2key::DSA_DSA,
    ),
    decoder(
        c"DSA",
        c"provider=default,fips=yes,input=msblob",
        &pending_keys::MSBLOB_DSA,
    ),
    decoder(
        c"DSA",
        c"provider=default,fips=yes,input=pvk",
        &pending_keys::PVK_DSA,
    ),
    decoder(
        c"EC",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_EC,
    ),
    decoder(
        c"EC",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_EC,
    ),
    decoder(
        c"EC",
        c"provider=default,fips=yes,input=der,structure=type-specific",
        &der2key::TS_EC,
    ),
    decoder(
        c"EC",
        c"provider=default,fips=yes,input=der,structure=ec",
        &der2key::EC_EC,
    ),
    decoder(
        c"ED25519",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_ED25519,
    ),
    decoder(
        c"ED25519",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_ED25519,
    ),
    decoder(
        c"ED448",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_ED448,
    ),
    decoder(
        c"ED448",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_ED448,
    ),
    decoder(
        c"X25519",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_X25519,
    ),
    decoder(
        c"X25519",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_X25519,
    ),
    decoder(
        c"X448",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_X448,
    ),
    decoder(
        c"X448",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_X448,
    ),
    decoder(
        c"SM2",
        c"provider=default,fips=no,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SM2,
    ),
    decoder(
        c"SM2",
        c"provider=default,fips=no,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SM2,
    ),
    decoder(
        c"SM2",
        c"provider=default,fips=no,input=der,structure=type-specific",
        &der2key::TS_SM2,
    ),
    decoder(
        c"ML-KEM-512",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_ML_KEM_512,
    ),
    decoder(
        c"ML-KEM-512",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_ML_KEM_512,
    ),
    decoder(
        c"ML-KEM-768",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_ML_KEM_768,
    ),
    decoder(
        c"ML-KEM-768",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_ML_KEM_768,
    ),
    decoder(
        c"ML-KEM-1024",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_ML_KEM_1024,
    ),
    decoder(
        c"ML-KEM-1024",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_ML_KEM_1024,
    ),
    decoder(
        c"SLH-DSA-SHA2-128s",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHA2_128S,
    ),
    decoder(
        c"SLH-DSA-SHA2-128f",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHA2_128F,
    ),
    decoder(
        c"SLH-DSA-SHA2-192s",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHA2_192S,
    ),
    decoder(
        c"SLH-DSA-SHA2-192f",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHA2_192F,
    ),
    decoder(
        c"SLH-DSA-SHA2-256s",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHA2_256S,
    ),
    decoder(
        c"SLH-DSA-SHA2-256f",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHA2_256F,
    ),
    decoder(
        c"SLH-DSA-SHAKE-128s",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHAKE_128S,
    ),
    decoder(
        c"SLH-DSA-SHAKE-128f",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHAKE_128F,
    ),
    decoder(
        c"SLH-DSA-SHAKE-192s",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHAKE_192S,
    ),
    decoder(
        c"SLH-DSA-SHAKE-192f",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHAKE_192F,
    ),
    decoder(
        c"SLH-DSA-SHAKE-256s",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHAKE_256S,
    ),
    decoder(
        c"SLH-DSA-SHAKE-256f",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHAKE_256F,
    ),
    decoder(
        c"SLH-DSA-SHA2-128s",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHA2_128S,
    ),
    decoder(
        c"SLH-DSA-SHA2-128f",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHA2_128F,
    ),
    decoder(
        c"SLH-DSA-SHA2-192s",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHA2_192S,
    ),
    decoder(
        c"SLH-DSA-SHA2-192f",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHA2_192F,
    ),
    decoder(
        c"SLH-DSA-SHA2-256s",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHA2_256S,
    ),
    decoder(
        c"SLH-DSA-SHA2-256f",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHA2_256F,
    ),
    decoder(
        c"SLH-DSA-SHAKE-128s",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHAKE_128S,
    ),
    decoder(
        c"SLH-DSA-SHAKE-128f",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHAKE_128F,
    ),
    decoder(
        c"SLH-DSA-SHAKE-192s",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHAKE_192S,
    ),
    decoder(
        c"SLH-DSA-SHAKE-192f",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHAKE_192F,
    ),
    decoder(
        c"SLH-DSA-SHAKE-256s",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHAKE_256S,
    ),
    decoder(
        c"SLH-DSA-SHAKE-256f",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHAKE_256F,
    ),
    decoder(
        c"RSA",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_RSA,
    ),
    decoder(
        c"RSA",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_RSA,
    ),
    decoder(
        c"RSA",
        c"provider=default,fips=yes,input=der,structure=type-specific",
        &der2key::TS_RSA,
    ),
    decoder(
        c"RSA",
        c"provider=default,fips=yes,input=der,structure=rsa",
        &der2key::RSA_RSA,
    ),
    decoder(
        c"RSA-PSS",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_RSAPSS,
    ),
    decoder(
        c"RSA-PSS",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_RSAPSS,
    ),
    decoder(
        c"RSA",
        c"provider=default,fips=yes,input=msblob",
        &pending_keys::MSBLOB_RSA,
    ),
    decoder(
        c"RSA",
        c"provider=default,fips=yes,input=pvk",
        &pending_keys::PVK_RSA,
    ),
    decoder(
        c"ML-DSA-44",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_ML_DSA_44,
    ),
    decoder(
        c"ML-DSA-65",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_ML_DSA_65,
    ),
    decoder(
        c"ML-DSA-87",
        c"provider=default,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_ML_DSA_87,
    ),
    decoder(
        c"ML-DSA-44",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_ML_DSA_44,
    ),
    decoder(
        c"ML-DSA-65",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_ML_DSA_65,
    ),
    decoder(
        c"ML-DSA-87",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_ML_DSA_87,
    ),
    decoder(
        c"DER",
        c"provider=default,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &SPKI_TO_DER,
    ),
    decoder(c"DER", c"provider=default,fips=yes,input=pem", &PEM_TO_DER),
    decoder(
        c"DER",
        c"provider=default,fips=yes,input=der,structure=EncryptedPrivateKeyInfo",
        &EPKI_TO_DER,
    ),
    super::tables::ALG_END,
]);

/// The base provider's, the same with its name.
static BASE_DECODERS: Algorithms<77> = Algorithms([
    decoder(
        c"DH",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_DH,
    ),
    decoder(
        c"DH",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_DH,
    ),
    decoder(
        c"DH",
        c"provider=base,fips=yes,input=der,structure=type-specific",
        &der2key::TS_DH,
    ),
    decoder(
        c"DH",
        c"provider=base,fips=yes,input=der,structure=dh",
        &der2key::DH_DH,
    ),
    decoder(
        c"DHX",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_DHX,
    ),
    decoder(
        c"DHX",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_DHX,
    ),
    decoder(
        c"DHX",
        c"provider=base,fips=yes,input=der,structure=type-specific",
        &der2key::TS_DHX,
    ),
    decoder(
        c"DHX",
        c"provider=base,fips=yes,input=der,structure=dhx",
        &der2key::DHX_DHX,
    ),
    decoder(
        c"DSA",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_DSA,
    ),
    decoder(
        c"DSA",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_DSA,
    ),
    decoder(
        c"DSA",
        c"provider=base,fips=yes,input=der,structure=type-specific",
        &der2key::TS_DSA,
    ),
    decoder(
        c"DSA",
        c"provider=base,fips=yes,input=der,structure=dsa",
        &der2key::DSA_DSA,
    ),
    decoder(
        c"DSA",
        c"provider=base,fips=yes,input=msblob",
        &pending_keys::MSBLOB_DSA,
    ),
    decoder(
        c"DSA",
        c"provider=base,fips=yes,input=pvk",
        &pending_keys::PVK_DSA,
    ),
    decoder(
        c"EC",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_EC,
    ),
    decoder(
        c"EC",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_EC,
    ),
    decoder(
        c"EC",
        c"provider=base,fips=yes,input=der,structure=type-specific",
        &der2key::TS_EC,
    ),
    decoder(
        c"EC",
        c"provider=base,fips=yes,input=der,structure=ec",
        &der2key::EC_EC,
    ),
    decoder(
        c"ED25519",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_ED25519,
    ),
    decoder(
        c"ED25519",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_ED25519,
    ),
    decoder(
        c"ED448",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_ED448,
    ),
    decoder(
        c"ED448",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_ED448,
    ),
    decoder(
        c"X25519",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_X25519,
    ),
    decoder(
        c"X25519",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_X25519,
    ),
    decoder(
        c"X448",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_X448,
    ),
    decoder(
        c"X448",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_X448,
    ),
    decoder(
        c"SM2",
        c"provider=base,fips=no,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SM2,
    ),
    decoder(
        c"SM2",
        c"provider=base,fips=no,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SM2,
    ),
    decoder(
        c"SM2",
        c"provider=base,fips=no,input=der,structure=type-specific",
        &der2key::TS_SM2,
    ),
    decoder(
        c"ML-KEM-512",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_ML_KEM_512,
    ),
    decoder(
        c"ML-KEM-512",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_ML_KEM_512,
    ),
    decoder(
        c"ML-KEM-768",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_ML_KEM_768,
    ),
    decoder(
        c"ML-KEM-768",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_ML_KEM_768,
    ),
    decoder(
        c"ML-KEM-1024",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_ML_KEM_1024,
    ),
    decoder(
        c"ML-KEM-1024",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_ML_KEM_1024,
    ),
    decoder(
        c"SLH-DSA-SHA2-128s",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHA2_128S,
    ),
    decoder(
        c"SLH-DSA-SHA2-128f",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHA2_128F,
    ),
    decoder(
        c"SLH-DSA-SHA2-192s",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHA2_192S,
    ),
    decoder(
        c"SLH-DSA-SHA2-192f",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHA2_192F,
    ),
    decoder(
        c"SLH-DSA-SHA2-256s",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHA2_256S,
    ),
    decoder(
        c"SLH-DSA-SHA2-256f",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHA2_256F,
    ),
    decoder(
        c"SLH-DSA-SHAKE-128s",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHAKE_128S,
    ),
    decoder(
        c"SLH-DSA-SHAKE-128f",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHAKE_128F,
    ),
    decoder(
        c"SLH-DSA-SHAKE-192s",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHAKE_192S,
    ),
    decoder(
        c"SLH-DSA-SHAKE-192f",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHAKE_192F,
    ),
    decoder(
        c"SLH-DSA-SHAKE-256s",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHAKE_256S,
    ),
    decoder(
        c"SLH-DSA-SHAKE-256f",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_SLH_DSA_SHAKE_256F,
    ),
    decoder(
        c"SLH-DSA-SHA2-128s",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHA2_128S,
    ),
    decoder(
        c"SLH-DSA-SHA2-128f",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHA2_128F,
    ),
    decoder(
        c"SLH-DSA-SHA2-192s",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHA2_192S,
    ),
    decoder(
        c"SLH-DSA-SHA2-192f",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHA2_192F,
    ),
    decoder(
        c"SLH-DSA-SHA2-256s",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHA2_256S,
    ),
    decoder(
        c"SLH-DSA-SHA2-256f",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHA2_256F,
    ),
    decoder(
        c"SLH-DSA-SHAKE-128s",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHAKE_128S,
    ),
    decoder(
        c"SLH-DSA-SHAKE-128f",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHAKE_128F,
    ),
    decoder(
        c"SLH-DSA-SHAKE-192s",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHAKE_192S,
    ),
    decoder(
        c"SLH-DSA-SHAKE-192f",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHAKE_192F,
    ),
    decoder(
        c"SLH-DSA-SHAKE-256s",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHAKE_256S,
    ),
    decoder(
        c"SLH-DSA-SHAKE-256f",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_SLH_DSA_SHAKE_256F,
    ),
    decoder(
        c"RSA",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_RSA,
    ),
    decoder(
        c"RSA",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_RSA,
    ),
    decoder(
        c"RSA",
        c"provider=base,fips=yes,input=der,structure=type-specific",
        &der2key::TS_RSA,
    ),
    decoder(
        c"RSA",
        c"provider=base,fips=yes,input=der,structure=rsa",
        &der2key::RSA_RSA,
    ),
    decoder(
        c"RSA-PSS",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_RSAPSS,
    ),
    decoder(
        c"RSA-PSS",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_RSAPSS,
    ),
    decoder(
        c"RSA",
        c"provider=base,fips=yes,input=msblob",
        &pending_keys::MSBLOB_RSA,
    ),
    decoder(
        c"RSA",
        c"provider=base,fips=yes,input=pvk",
        &pending_keys::PVK_RSA,
    ),
    decoder(
        c"ML-DSA-44",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_ML_DSA_44,
    ),
    decoder(
        c"ML-DSA-65",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_ML_DSA_65,
    ),
    decoder(
        c"ML-DSA-87",
        c"provider=base,fips=yes,input=der,structure=PrivateKeyInfo",
        &der2key::P8_ML_DSA_87,
    ),
    decoder(
        c"ML-DSA-44",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_ML_DSA_44,
    ),
    decoder(
        c"ML-DSA-65",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_ML_DSA_65,
    ),
    decoder(
        c"ML-DSA-87",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &der2key::SPKI_ML_DSA_87,
    ),
    decoder(
        c"DER",
        c"provider=base,fips=yes,input=der,structure=SubjectPublicKeyInfo",
        &SPKI_TO_DER,
    ),
    decoder(c"DER", c"provider=base,fips=yes,input=pem", &PEM_TO_DER),
    decoder(
        c"DER",
        c"provider=base,fips=yes,input=der,structure=EncryptedPrivateKeyInfo",
        &EPKI_TO_DER,
    ),
    super::tables::ALG_END,
]);

/// `deflt_decoder`.
pub(crate) fn default_decoders() -> *const OSSL_ALGORITHM {
    DEFAULT_DECODERS.0.as_ptr()
}

/// `base_decoder`.
pub(crate) fn base_decoders() -> *const OSSL_ALGORITHM {
    BASE_DECODERS.0.as_ptr()
}
