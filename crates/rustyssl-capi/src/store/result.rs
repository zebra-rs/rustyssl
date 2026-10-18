//! What a provider's loader gives, made into an `OSSL_STORE_INFO` (`store_result.c`): a name;
//! a key by reference or by value (through the decoders, then the legacy DER forms); a
//! certificate; a CRL; or a PKCS #12 file's key, certificate, and chain, given one by one.

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;
use std::collections::VecDeque;

use rustyssl_abi::{
    ERR_LIB_OSSL_STORE, ERR_R_UNSUPPORTED, EVP_PKEY, OSSL_KEYMGMT_SELECT_ALL,
    OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_LIB_CTX, OSSL_OBJECT_CERT, OSSL_OBJECT_CRL,
    OSSL_OBJECT_NAME, OSSL_OBJECT_PARAM_DATA, OSSL_OBJECT_PARAM_DATA_STRUCTURE,
    OSSL_OBJECT_PARAM_DATA_TYPE, OSSL_OBJECT_PARAM_DESC, OSSL_OBJECT_PARAM_INPUT_TYPE,
    OSSL_OBJECT_PARAM_REFERENCE, OSSL_OBJECT_PARAM_TYPE, OSSL_OBJECT_PKEY, OSSL_OBJECT_UNKNOWN,
    OSSL_PARAM, OSSL_PARAM_UTF8_STRING, OSSL_PASSPHRASE_PARAM_INFO, OSSL_PROVIDER, OSSL_STORE_CTX,
    OSSL_STORE_INFO, OSSL_STORE_INFO_PARAMS, OSSL_STORE_INFO_PKEY, OSSL_STORE_INFO_PUBKEY,
    OSSL_STORE_R_BAD_PASSWORD_READ, OSSL_STORE_R_ERROR_VERIFYING_PKCS12_MAC,
    OSSL_STORE_R_PASSPHRASE_CALLBACK_ERROR, PEM_BUFSIZE, PEM_STRING_X509_TRUSTED, X509,
};

use super::ctx::ctx_of;
use super::info::{
    OSSL_STORE_INFO_free, OSSL_STORE_INFO_new_CERT, OSSL_STORE_INFO_new_CRL,
    OSSL_STORE_INFO_new_NAME, OSSL_STORE_INFO_new_PARAMS, OSSL_STORE_INFO_new_PKEY,
    OSSL_STORE_INFO_new_PUBKEY, OSSL_STORE_INFO_set0_NAME_description, strdup,
};
use super::meth::provided;
use crate::decoder::ctx::{
    OSSL_DECODER_CTX_free, OSSL_DECODER_CTX_set_passphrase_cb, OSSL_DECODER_from_data,
    ctx as decoder_ctx,
};
use crate::decoder::pkey::{OSSL_DECODER_CTX_new_for_pkey, make_pkey};
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::keymgmt::{self, EVP_KEYMGMT_fetch};
use crate::evp::pkey::d2i::EVP_PKCS82PKEY_ex;
use crate::evp::pkey::{EVP_PKEY_free, TryImport, pkey, try_import, util_has};
use crate::ffi::ffi_callback;
use crate::mem;
use crate::params::{
    OSSL_PARAM_get_int, OSSL_PARAM_get_octet_string_ptr, OSSL_PARAM_get_utf8_string_ptr,
    OSSL_PARAM_locate_const,
};
use crate::passphrase::{PwData, passphrase_callback_dec};
use crate::pkcs8_crypt::PKCS12_pbe_crypt;
use crate::pkcs12::asn::{PKCS12_free, d2i_PKCS12};
use crate::pkcs12::kiss::PKCS12_parse;
use crate::pkcs12::mutl::{PKCS12_mac_present, PKCS12_verify_mac};
use crate::provider::{OSSL_PROVIDER_available, OSSL_PROVIDER_get0_name, libctx_of};
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_shift};
use crate::x509::cert::{OSSL_STACK_OF_X509_free, X509_free, X509_new_ex, d2i_X509, d2i_X509_AUX};
use crate::x509::crl::{X509_CRL_free, d2i_X509_CRL};
use crate::x509::p8::{PKCS8_PRIV_KEY_INFO_free, d2i_PKCS8_PRIV_KEY_INFO};
use crate::x509::pubkey::d2i_PUBKEY_ex;
use crate::x509::sig::{X509_SIG_free, X509_SIG_get0, d2i_X509_SIG};

/// `ossl_load_result_data_st`: what `OSSL_STORE_load` gets back, and the store.
pub(crate) struct LoadData {
    pub(crate) v: *mut OSSL_STORE_INFO,
    pub(crate) ctx: *mut OSSL_STORE_CTX,
}

/// `extracted_param_data_st`: the object's parameters (pointers into the loader's).
struct Extracted {
    object_type: c_int,
    data_type: *const c_char,
    input_type: *const c_char,
    data_structure: *const c_char,
    utf8_data: *const c_char,
    octet_data: *const c_void,
    octet_data_size: usize,
    reference: *const c_void,
    ref_size: usize,
    desc: *const c_char,
}

/// The parameters into `e`: false if one is of the wrong type.
///
/// # Safety
/// `params` is a parameter array.
unsafe fn extract(params: *const OSSL_PARAM, e: &mut Extracted) -> bool {
    let locate = |k: &CStr| {
        // SAFETY: the caller's array.
        unsafe { OSSL_PARAM_locate_const(params, k.as_ptr()) }
    };
    let p = locate(OSSL_OBJECT_PARAM_TYPE);
    // SAFETY: a located parameter; room for the value.
    if !p.is_null() && unsafe { OSSL_PARAM_get_int(p, &raw mut e.object_type) } == 0 {
        return false;
    }
    let p = locate(OSSL_OBJECT_PARAM_DATA_TYPE);
    // SAFETY: as above.
    if !p.is_null() && unsafe { OSSL_PARAM_get_utf8_string_ptr(p, &raw mut e.data_type) } == 0 {
        return false;
    }
    let p = locate(OSSL_OBJECT_PARAM_DATA);
    if !p.is_null()
        // SAFETY: as above.
        && unsafe { OSSL_PARAM_get_octet_string_ptr(p, &raw mut e.octet_data, &raw mut e.octet_data_size) } == 0
        // SAFETY: as above.
        && unsafe { OSSL_PARAM_get_utf8_string_ptr(p, &raw mut e.utf8_data) } == 0
    {
        return false;
    }
    for (key, slot) in [
        (OSSL_OBJECT_PARAM_DATA_STRUCTURE, &mut e.data_structure),
        (OSSL_OBJECT_PARAM_INPUT_TYPE, &mut e.input_type),
    ] {
        let p = locate(key);
        // SAFETY: as above.
        if !p.is_null() && unsafe { OSSL_PARAM_get_utf8_string_ptr(p, slot) } == 0 {
            return false;
        }
    }
    let p = locate(OSSL_OBJECT_PARAM_REFERENCE);
    if !p.is_null()
        // SAFETY: as above.
        && unsafe { OSSL_PARAM_get_octet_string_ptr(p, &raw mut e.reference, &raw mut e.ref_size) }
            == 0
    {
        return false;
    }
    let p = locate(OSSL_OBJECT_PARAM_DESC);
    // SAFETY: as above.
    !(!p.is_null() && unsafe { OSSL_PARAM_get_utf8_string_ptr(p, &raw mut e.desc) } == 0)
}

ffi_callback! {
    /// `ossl_store_handle_load_result`: the loader's object as an `OSSL_STORE_INFO` into the
    /// load data: 1, or 0.
    ///
    /// # Safety
    /// `params` is a parameter array; `arg` a live [`LoadData`].
    pub(crate) unsafe extern "C" fn handle_load_result(params: *const OSSL_PARAM, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        let Some(data) = (unsafe { arg.cast::<LoadData>().as_mut() }) else { return 0 };
        let ctx = data.ctx;
        // SAFETY: the store's live context; its loader.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        let prov = if c.fetched {
            // SAFETY: its loader.
            unsafe { provided(c.loader) }.map_or(ptr::null_mut(), |p| p.prov.0)
        } else {
            ptr::null_mut()
        };
        // SAFETY: the provider, or NULL.
        let libctx = if prov.is_null() { ptr::null_mut() } else { unsafe { libctx_of(prov) } };
        let propq = c.properties.cast_const();
        let mut e = Extracted {
            object_type: OSSL_OBJECT_UNKNOWN,
            data_type: ptr::null(),
            input_type: ptr::null(),
            data_structure: ptr::null(),
            utf8_data: ptr::null(),
            octet_data: ptr::null(),
            octet_data_size: 0,
            reference: ptr::null(),
            ref_size: 0,
            desc: ptr::null(),
        };
        // SAFETY: the caller's array.
        if !unsafe { extract(params, &mut e) } {
            return 0;
        }
        let v = &mut data.v;
        /// One try under an error mark: on failure the mark's errors stay and the result is 0.
        macro_rules! attempt {
            ($e:expr) => {
                // SAFETY: no preconditions.
                unsafe { ERR_set_mark() };
                if v.is_null() && !$e {
                    // SAFETY: the mark set above.
                    unsafe { ERR_clear_last_mark() };
                    return 0;
                }
                // SAFETY: as above.
                unsafe { ERR_pop_to_mark() };
            };
        }
        // SAFETY: the extracted pointers, valid during the callback; the store's context.
        attempt!(unsafe { try_name(&e, v) });
        // SAFETY: as above.
        attempt!(unsafe { try_key(&mut e, v, ctx, prov, libctx, propq) });
        // SAFETY: as above.
        attempt!(unsafe { try_cert(&mut e, v, libctx, propq) });
        // SAFETY: as above.
        attempt!(unsafe { try_crl(&mut e, v) });
        // SAFETY: as above.
        attempt!(unsafe { try_pkcs12(&mut e, v, ctx) });
        if v.is_null() {
            // SAFETY: the library context, or NULL for the default one.
            let hint = if unsafe { OSSL_PROVIDER_available(libctx, c"default".as_ptr()) } == 0 {
                ":maybe need to load the default provider?"
            } else {
                ""
            };
            if !prov.is_null() {
                // SAFETY: the loader's provider.
                let n = unsafe { OSSL_PROVIDER_get0_name(prov) };
                // SAFETY: its name.
                let name = unsafe { CStr::from_ptr(n) }.to_string_lossy();
                err::raise_with_text(ERR_LIB_OSSL_STORE, ERR_R_UNSUPPORTED, "ossl_store_handle_load_result", &format!("provider={name}{hint}"));
            } else if !hint.is_empty() {
                err::raise_with_text(ERR_LIB_OSSL_STORE, ERR_R_UNSUPPORTED, "ossl_store_handle_load_result", hint);
            } else {
                err::raise(ERR_LIB_OSSL_STORE, ERR_R_UNSUPPORTED, "ossl_store_handle_load_result");
            }
        }
        c_int::from(!v.is_null())
    }
}

/// `try_name`.
///
/// # Safety
/// `e`'s strings are NULL or C strings.
unsafe fn try_name(e: &Extracted, v: &mut *mut OSSL_STORE_INFO) -> bool {
    if e.object_type != OSSL_OBJECT_NAME {
        return true;
    }
    if e.utf8_data.is_null() {
        return false;
    }
    // SAFETY: a C string.
    let name = unsafe { strdup(e.utf8_data) };
    let desc = if e.desc.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: as above.
        unsafe { strdup(e.desc) }
    };
    let made = if name.is_null() || (!e.desc.is_null() && desc.is_null()) {
        ptr::null_mut()
    } else {
        // SAFETY: the copy, which the information takes.
        unsafe { OSSL_STORE_INFO_new_NAME(name) }
    };
    if made.is_null() {
        // SAFETY: from `CRYPTO_malloc`, or NULL.
        unsafe { mem::release(name.cast()) };
        // SAFETY: as above.
        unsafe { mem::release(desc.cast()) };
        return false;
    }
    // SAFETY: the new name; the description, which it takes.
    unsafe { OSSL_STORE_INFO_set0_NAME_description(made, desc) };
    *v = made;
    true
}

/// `try_key_ref`: the key the loader refers to, loaded by the key manager of the loader's
/// provider, or imported through the loader's export.
///
/// # Safety
/// `e`'s strings are NULL or C strings; `ctx` a live store context; `prov` its loader's
/// provider.
unsafe fn try_key_ref(
    e: &Extracted,
    ctx: *mut OSSL_STORE_CTX,
    prov: *mut OSSL_PROVIDER,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> *mut EVP_PKEY {
    if e.data_type.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a C string.
    let data_type = unsafe { CStr::from_ptr(e.data_type) };
    // SAFETY: a C string, or NULL.
    let props = (!propq.is_null()).then(|| unsafe { CStr::from_ptr(propq) });
    // SAFETY: the library context; a C string; the properties.
    let m = unsafe { EVP_KEYMGMT_fetch(libctx, e.data_type, propq) };
    // SAFETY: a new reference, or NULL.
    let mut km = unsafe { keymgmt::Ref::adopt(m) };
    let mut keydata: *mut c_void = ptr::null_mut();
    let mut try_fallback = 2;
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    while let Some(r) = km
        .as_ref()
        .filter(|_| keydata.is_null() && try_fallback > 0)
    {
        try_fallback -= 1;
        if r.get().prov.0 == prov {
            try_fallback = 0;
            // SAFETY: the loader's reference.
            keydata = unsafe { r.get().load(e.reference, e.ref_size) };
        } else {
            let mut import = TryImport {
                keymgmt: r.clone(),
                keydata: ptr::null_mut(),
                selection: OSSL_KEYMGMT_SELECT_ALL,
                allocated: false,
            };
            // SAFETY: the store's context.
            let (lctx, export) = match unsafe { ctx_of(ctx) } {
                // SAFETY: its loader.
                Some(c) => (
                    c.loader_ctx,
                    unsafe { provided(c.loader) }.and_then(|p| p.export_object),
                ),
                None => (ptr::null_mut(), None),
            };
            if let Some(export) = export {
                // SAFETY: the loader's function on its context and reference; the import data,
                // which outlives the call.
                unsafe {
                    export(
                        lctx,
                        e.reference,
                        e.ref_size,
                        Some(try_import),
                        (&raw mut import).cast(),
                    )
                };
            }
            keydata = import.keydata;
        }
        if keydata.is_null() && try_fallback > 0 {
            // SAFETY: the loader's provider.
            km = unsafe { keymgmt::fetch_from_prov(prov, data_type, props) };
            if km.is_some() {
                // SAFETY: the mark set above.
                unsafe { ERR_pop_to_mark() };
                // SAFETY: no preconditions.
                unsafe { ERR_set_mark() };
            }
        }
    }
    if keydata.is_null() {
        // SAFETY: as above.
        unsafe { ERR_clear_last_mark() };
        return ptr::null_mut();
    }
    // SAFETY: as above.
    unsafe { ERR_pop_to_mark() };
    match km {
        // SAFETY: its new key data, which the key takes.
        Some(r) => unsafe { make_pkey(&r, keydata) },
        None => ptr::null_mut(),
    }
}

/// `try_key_value`: the key decoded from the octets by the decoders, with whether a key
/// manager refused what they decoded (`harderr`).
///
/// # Safety
/// `e`'s pointers are NULL or valid; `c` the store's context; `pw` its passphrase data.
unsafe fn try_key_value(
    e: &Extracted,
    expected_type: c_int,
    pw: *mut PwData,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> (*mut EVP_PKEY, bool) {
    let selection = match expected_type {
        0 => 0,
        OSSL_STORE_INFO_PARAMS => OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
        OSSL_STORE_INFO_PUBKEY => {
            OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS
        }
        OSSL_STORE_INFO_PKEY => OSSL_KEYMGMT_SELECT_ALL,
        _ => return (ptr::null_mut(), false),
    };
    let mut pk = ptr::null_mut();
    // SAFETY: room for the key; the object's strings; the library context and properties.
    let dctx = unsafe {
        OSSL_DECODER_CTX_new_for_pkey(
            &raw mut pk,
            e.input_type,
            e.data_structure,
            e.data_type,
            selection,
            libctx,
            propq,
        )
    };
    // SAFETY: the context, or NULL; the passphrase callback over the store's data.
    unsafe { OSSL_DECODER_CTX_set_passphrase_cb(dctx, Some(passphrase_callback_dec), pw.cast()) };
    let mut pdata = e.octet_data.cast::<c_uchar>();
    let mut plen = e.octet_data_size;
    // SAFETY: as above; the octets.
    unsafe { OSSL_DECODER_from_data(dctx, &raw mut pdata, &raw mut plen) };
    // SAFETY: as above.
    let harderr = unsafe { decoder_ctx(dctx) }.is_some_and(|c| c.lock().harderr);
    // SAFETY: as above.
    unsafe { OSSL_DECODER_CTX_free(dctx) };
    (pk, harderr)
}

type InfoNew = unsafe extern "C" fn(*mut EVP_PKEY) -> *mut OSSL_STORE_INFO;

/// `try_key_value_legacy`: the key from a `SubjectPublicKeyInfo`, or from a PKCS #8 key
/// (encrypted, decrypted with the passphrase), with the kind of information it makes.
///
/// # Safety
/// `e`'s octets are valid; `pw` the store's passphrase data.
unsafe fn try_key_value_legacy(
    e: &Extracted,
    expected_type: c_int,
    pw: *mut PwData,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> (*mut EVP_PKEY, Option<InfoNew>) {
    let der = e.octet_data.cast::<c_uchar>();
    let Ok(der_len) = c_long::try_from(e.octet_data_size) else {
        return (ptr::null_mut(), None);
    };
    if expected_type == 0 || expected_type == OSSL_STORE_INFO_PUBKEY {
        let mut p = der;
        // SAFETY: the octets; the library context and properties.
        let pk = unsafe { d2i_PUBKEY_ex(ptr::null_mut(), &raw mut p, der_len, libctx, propq) };
        if !pk.is_null() {
            return (pk, Some(OSSL_STORE_INFO_new_PUBKEY));
        }
    }
    if expected_type != 0 && expected_type != OSSL_STORE_INFO_PKEY {
        return (ptr::null_mut(), None);
    }
    let (mut der, mut der_len) = (der, der_len);
    let mut new_der: *mut c_uchar = ptr::null_mut();
    let mut p = der;
    // SAFETY: the octets.
    let p8 = unsafe { d2i_X509_SIG(ptr::null_mut(), &raw mut p, der_len) };
    if !p8.is_null() {
        let mut pbuf = [0 as c_char; PEM_BUFSIZE as usize];
        let mut plen = 0usize;
        // SAFETY: the room; the store's passphrase data.
        if unsafe {
            passphrase_callback_dec(
                pbuf.as_mut_ptr(),
                pbuf.len(),
                &raw mut plen,
                ptr::null(),
                pw.cast(),
            )
        } == 0
        {
            err::raise(
                ERR_LIB_OSSL_STORE,
                OSSL_STORE_R_BAD_PASSWORD_READ,
                "try_key_value_legacy",
            );
        } else {
            let (mut alg, mut oct) = (ptr::null(), ptr::null());
            // SAFETY: the signature decoded; rooms for its parts.
            unsafe { X509_SIG_get0(p8, &raw mut alg, &raw mut oct) };
            let mut len: c_int = 0;
            let plen = c_int::try_from(plen).unwrap_or(0);
            // SAFETY: the signature's octets.
            let (data, dlen) = unsafe { oct.as_ref() }
                .map_or((ptr::null(), 0), |o| (o.data.cast_const(), o.length));
            // SAFETY: its parts; the passphrase; rooms for the output.
            unsafe {
                PKCS12_pbe_crypt(
                    alg,
                    pbuf.as_ptr(),
                    plen,
                    data,
                    dlen,
                    &raw mut new_der,
                    &raw mut len,
                    0,
                )
            };
            der_len = c_long::from(len);
            der = new_der;
        }
        // SAFETY: the passphrase's room.
        unsafe { mem::cleanse(pbuf.as_mut_ptr().cast(), pbuf.len()) };
        // SAFETY: decoded here.
        unsafe { X509_SIG_free(p8) };
    }
    let mut pk = ptr::null_mut();
    if !der.is_null() {
        let mut p = der;
        // SAFETY: the octets (decrypted, or the input).
        let p8info = unsafe { d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), &raw mut p, der_len) };
        if !p8info.is_null() {
            // SAFETY: the key info; the library context and properties.
            pk = unsafe { EVP_PKCS82PKEY_ex(p8info, libctx, propq) };
            // SAFETY: decoded here.
            unsafe { PKCS8_PRIV_KEY_INFO_free(p8info) };
        }
    }
    // SAFETY: from `CRYPTO_malloc`, or NULL.
    unsafe { mem::release(new_der.cast()) };
    let new = (!pk.is_null()).then_some(OSSL_STORE_INFO_new_PKEY as InfoNew);
    (pk, new)
}

/// `try_key`: false on a hard error (a key manager refused what was decoded).
///
/// # Safety
/// `e`'s pointers are NULL or valid; `ctx` a live store context.
unsafe fn try_key(
    e: &mut Extracted,
    v: &mut *mut OSSL_STORE_INFO,
    ctx: *mut OSSL_STORE_CTX,
    prov: *mut OSSL_PROVIDER,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> bool {
    if e.object_type != OSSL_OBJECT_UNKNOWN && e.object_type != OSSL_OBJECT_PKEY {
        return true;
    }
    // SAFETY: the caller's context.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return true;
    };
    let expected_type = c.expected_type;
    let pw = ptr::from_mut::<PwData>(&mut c.pwdata);
    let mut harderr = false;
    let mut new: Option<InfoNew> = None;
    let mut pk = ptr::null_mut();
    if e.object_type == OSSL_OBJECT_PKEY && !e.reference.is_null() {
        // SAFETY: as above.
        pk = unsafe { try_key_ref(e, ctx, prov, libctx, propq) };
        if pk.is_null() {
            return false;
        }
    } else if !e.octet_data.is_null() {
        // SAFETY: as above.
        (pk, harderr) = unsafe { try_key_value(e, expected_type, pw, libctx, propq) };
        if pk.is_null() && !harderr {
            // SAFETY: as above.
            (pk, new) = unsafe { try_key_value_legacy(e, expected_type, pw, libctx, propq) };
        }
    }
    if !pk.is_null() {
        e.object_type = OSSL_OBJECT_PKEY;
        let new = new.unwrap_or_else(|| {
            // SAFETY: the key made here.
            let k = unsafe { pkey(pk) };
            if k.is_some_and(|k| util_has(k, OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) {
                OSSL_STORE_INFO_new_PKEY
            } else if k.is_some_and(|k| util_has(k, OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) {
                OSSL_STORE_INFO_new_PUBKEY
            } else {
                OSSL_STORE_INFO_new_PARAMS
            }
        });
        // SAFETY: the key, which the information takes.
        *v = unsafe { new(pk) };
    }
    if v.is_null() {
        // SAFETY: the key made here, or NULL.
        unsafe { EVP_PKEY_free(pk) };
    }
    !harderr
}

/// `try_cert`.
///
/// # Safety
/// `e`'s pointers are NULL or valid.
unsafe fn try_cert(
    e: &mut Extracted,
    v: &mut *mut OSSL_STORE_INFO,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> bool {
    if e.object_type != OSSL_OBJECT_UNKNOWN && e.object_type != OSSL_OBJECT_CERT {
        return true;
    }
    if e.octet_data.is_null() {
        // Nothing to decode: OpenSSL's decode fails on it.
        return true;
    }
    // SAFETY: the library context and properties.
    let mut cert: *mut X509 = unsafe { X509_new_ex(libctx, propq) };
    if cert.is_null() {
        return false;
    }
    // SAFETY: a C string, or NULL.
    let ignore_trusted = e.data_type.is_null()
        || !unsafe { CStr::from_ptr(e.data_type) }
            .to_bytes()
            .eq_ignore_ascii_case(PEM_STRING_X509_TRUSTED.to_bytes());
    let Ok(len) = c_long::try_from(e.octet_data_size) else {
        return true;
    };
    // Both decodes read on from where the other left `octet_data`, as OpenSSL's do.
    let mut p = e.octet_data.cast::<c_uchar>();
    // SAFETY: the certificate made here; the octets.
    let aux = unsafe { d2i_X509_AUX(&raw mut cert, &raw mut p, len) };
    e.octet_data = p.cast();
    let mut ok = !aux.is_null();
    if !ok && ignore_trusted {
        let mut p = e.octet_data.cast::<c_uchar>();
        // SAFETY: as above.
        ok = !unsafe { d2i_X509(&raw mut cert, &raw mut p, len) }.is_null();
        e.octet_data = p.cast();
    }
    if !ok {
        // SAFETY: the certificate made here (or freed and cleared by a failed decode).
        unsafe { X509_free(cert) };
        return true;
    }
    e.object_type = OSSL_OBJECT_CERT;
    // SAFETY: the certificate, which the information takes.
    *v = unsafe { OSSL_STORE_INFO_new_CERT(cert) };
    if v.is_null() {
        // SAFETY: as above.
        unsafe { X509_free(cert) };
    }
    true
}

/// `try_crl`.
///
/// # Safety
/// `e`'s pointers are NULL or valid.
unsafe fn try_crl(e: &mut Extracted, v: &mut *mut OSSL_STORE_INFO) -> bool {
    if e.object_type != OSSL_OBJECT_UNKNOWN && e.object_type != OSSL_OBJECT_CRL {
        return true;
    }
    if e.octet_data.is_null() {
        // Nothing to decode: OpenSSL's decode fails on it.
        return true;
    }
    let Ok(len) = c_long::try_from(e.octet_data_size) else {
        return true;
    };
    let mut p = e.octet_data.cast::<c_uchar>();
    // SAFETY: the octets.
    let crl = unsafe { d2i_X509_CRL(ptr::null_mut(), &raw mut p, len) };
    e.octet_data = p.cast();
    if !crl.is_null() {
        e.object_type = OSSL_OBJECT_CRL;
        // SAFETY: the CRL, which the information takes.
        *v = unsafe { OSSL_STORE_INFO_new_CRL(crl) };
    }
    if v.is_null() {
        // SAFETY: decoded here, or NULL.
        unsafe { X509_CRL_free(crl) };
    }
    true
}

/// The PKCS #12 file's key, certificate, and chain as informations, or `None`.
///
/// # Safety
/// The arguments are what `PKCS12_parse` gave, which this takes.
unsafe fn p12_infos(
    pkey: *mut EVP_PKEY,
    cert: *mut X509,
    chain: *mut rustyssl_abi::stack_st_X509,
) -> Option<VecDeque<*mut OSSL_STORE_INFO>> {
    let mut infos = VecDeque::new();
    let mut ok = true;
    if !pkey.is_null() {
        // SAFETY: the key, which the information takes.
        let i = unsafe { OSSL_STORE_INFO_new_PKEY(pkey) };
        if i.is_null() {
            // SAFETY: as above, kept on failure.
            unsafe { EVP_PKEY_free(pkey) };
            ok = false;
        } else {
            infos.push_back(i);
        }
    }
    if !cert.is_null() {
        if ok {
            // SAFETY: the certificate, which the information takes.
            let i = unsafe { OSSL_STORE_INFO_new_CERT(cert) };
            if i.is_null() {
                // SAFETY: as above.
                unsafe { X509_free(cert) };
                ok = false;
            } else {
                infos.push_back(i);
            }
        } else {
            // SAFETY: as above.
            unsafe { X509_free(cert) };
        }
    }
    // SAFETY: the chain, or NULL (0).
    while ok && unsafe { OPENSSL_sk_num(chain.cast()) } > 0 {
        // SAFETY: as above.
        let ca: *mut X509 = unsafe { OPENSSL_sk_shift(chain.cast()) }.cast();
        // SAFETY: the certificate taken from the chain, which the information takes.
        let i = unsafe { OSSL_STORE_INFO_new_CERT(ca) };
        if i.is_null() {
            // SAFETY: as above.
            unsafe { X509_free(ca) };
            ok = false;
        } else {
            infos.push_back(i);
        }
    }
    // SAFETY: what is left of the chain, or NULL.
    unsafe { OSSL_STACK_OF_X509_free(chain) };
    if !ok {
        for i in infos {
            // SAFETY: made here.
            unsafe { OSSL_STORE_INFO_free(i) };
        }
        return None;
    }
    Some(infos)
}

/// The passphrase of a PKCS #12 file whose MAC needs one: from the store's passphrase source,
/// and checked against the MAC. `Err` with the error raised.
///
/// # Safety
/// `p12` is a live PKCS #12 file; `pw` the store's passphrase data.
unsafe fn p12_pass(
    p12: *mut rustyssl_abi::PKCS12,
    pw: *mut PwData,
    tpass: &mut [c_char],
) -> Result<*const c_char, ()> {
    // SAFETY: the caller's file.
    if unsafe { PKCS12_mac_present(p12) } == 0
        // SAFETY: as above.
        || unsafe { PKCS12_verify_mac(p12, ptr::null(), 0) } != 0
    {
        return Ok(ptr::null());
    }
    // SAFETY: as above.
    if unsafe { PKCS12_verify_mac(p12, c"".as_ptr(), 0) } != 0 {
        return Ok(c"".as_ptr());
    }
    let prompt = c"PKCS12 import pass phrase";
    let params = [
        OSSL_PARAM {
            key: OSSL_PASSPHRASE_PARAM_INFO.as_ptr(),
            data_type: OSSL_PARAM_UTF8_STRING.cast_unsigned(),
            data: prompt.as_ptr().cast_mut().cast(),
            data_size: prompt.to_bytes().len(),
            return_size: usize::MAX,
        },
        OSSL_PARAM {
            key: ptr::null(),
            data_type: 0,
            data: ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
    ];
    let mut len = 0usize;
    let room = tpass.len().saturating_sub(1);
    // SAFETY: the room (one left for the NUL); the prompt; the store's data.
    if !unsafe {
        PwData::get(
            pw,
            tpass.as_mut_ptr(),
            room,
            &raw mut len,
            params.as_ptr(),
            false,
        )
    } {
        err::raise(
            ERR_LIB_OSSL_STORE,
            OSSL_STORE_R_PASSPHRASE_CALLBACK_ERROR,
            "try_pkcs12",
        );
        return Err(());
    }
    if let Some(x) = tpass.get_mut(len) {
        *x = 0;
    }
    let ilen = c_int::try_from(len).unwrap_or(-1);
    // SAFETY: the file; the passphrase.
    if unsafe { PKCS12_verify_mac(p12, tpass.as_ptr(), ilen) } == 0 {
        let why = if len == 0 {
            "empty password"
        } else {
            "maybe wrong password"
        };
        err::raise_with_text(
            ERR_LIB_OSSL_STORE,
            OSSL_STORE_R_ERROR_VERIFYING_PKCS12_MAC,
            "try_pkcs12",
            why,
        );
        return Err(());
    }
    Ok(tpass.as_ptr())
}

/// `try_pkcs12`: a PKCS #12 file's objects, the first into `*v` and the rest into the store's
/// cache. False when its passphrase couldn't be had or it couldn't be parsed.
///
/// # Safety
/// `e`'s octets are valid; `ctx` a live store context.
unsafe fn try_pkcs12(
    e: &mut Extracted,
    v: &mut *mut OSSL_STORE_INFO,
    ctx: *mut OSSL_STORE_CTX,
) -> bool {
    if e.object_type != OSSL_OBJECT_UNKNOWN {
        return true;
    }
    if e.octet_data.is_null() {
        // Nothing to decode: OpenSSL's decode fails on it.
        return true;
    }
    let Ok(len) = c_long::try_from(e.octet_data_size) else {
        return true;
    };
    let mut p = e.octet_data.cast::<c_uchar>();
    // SAFETY: the octets.
    let p12 = unsafe { d2i_PKCS12(ptr::null_mut(), &raw mut p, len) };
    e.octet_data = p.cast();
    let mut ok = true;
    // SAFETY: the caller's context.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return true;
    };
    if !p12.is_null() {
        e.object_type = -1;
        ok = false;
        let pw = ptr::from_mut::<PwData>(&mut c.pwdata);
        let mut tpass = [0 as c_char; PEM_BUFSIZE as usize + 1];
        // SAFETY: the file; the store's data; the room.
        if let Ok(pass) = unsafe { p12_pass(p12, pw, &mut tpass) } {
            let (mut pkey, mut cert, mut chain) =
                (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
            // SAFETY: the file; the passphrase; rooms for what it holds.
            if unsafe { PKCS12_parse(p12, pass, &raw mut pkey, &raw mut cert, &raw mut chain) } != 0
            {
                // SAFETY: what it gave, which this takes.
                let infos = unsafe { p12_infos(pkey, cert, chain) };
                ok = infos.is_some();
                // SAFETY: as above, after the callbacks.
                if let Some(c) = unsafe { ctx_of(ctx) } {
                    c.cached_info = infos;
                }
            }
        }
        // SAFETY: the room.
        unsafe { mem::cleanse(tpass.as_mut_ptr().cast(), tpass.len()) };
        // SAFETY: decoded here.
        unsafe { PKCS12_free(p12) };
    }
    // SAFETY: as above.
    if let Some(c) = unsafe { ctx_of(ctx) } {
        *v = c
            .cached_info
            .as_mut()
            .and_then(VecDeque::pop_front)
            .unwrap_or(ptr::null_mut());
    }
    ok
}
