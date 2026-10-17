//! The MSBLOB and PVK key decoders (`decode_msblob2key.c`, `decode_pvk2key.c`): RSA and DSA
//! keys read by `pvkfmt`'s readers, passed on by reference, and exported through the key
//! managers.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PEM, ERR_LIB_PROV, OSSL_CALLBACK, OSSL_CORE_BIO, OSSL_DECODER_PARAM_PROPERTIES,
    OSSL_FUNC_DECODER_DECODE, OSSL_FUNC_DECODER_DOES_SELECTION, OSSL_FUNC_DECODER_EXPORT_OBJECT,
    OSSL_FUNC_DECODER_FREECTX, OSSL_FUNC_DECODER_NEWCTX, OSSL_FUNC_DECODER_SET_CTX_PARAMS,
    OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, OSSL_KEYMGMT_SELECT_ALL,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_OBJECT_PARAM_DATA_TYPE,
    OSSL_OBJECT_PARAM_REFERENCE, OSSL_OBJECT_PARAM_TYPE, OSSL_OBJECT_PKEY, OSSL_PARAM,
    OSSL_PASSPHRASE_CALLBACK, PEM_R_BAD_DECRYPT, PEM_R_BAD_PASSWORD_READ, PEM_R_HEADER_TOO_LONG,
    PEM_R_KEYBLOB_TOO_SHORT,
};

use super::builtin::libctx_of;
use super::decoders::{props_settable_ctx_params, read_into};
use super::dsa_kmgmt::dsa_export;
use super::rsa_kmgmt::rsa_export;
use super::tables::{Dispatch, END, entry};
use crate::decoder::ctx::bio_new_from_core_bio;
use crate::err::{self, ERR_clear_last_mark, ERR_peek_last_error, ERR_pop_to_mark, ERR_set_mark};
use crate::ffi::ffi_callback;
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_utf8_string,
};
use crate::passphrase::{PwData, pw_pvk_password};
use crate::pvkfmt;

/// `OSSL_MAX_PROPQUERY_SIZE` (`internal/sizes.h`).
const MAX_PROPQUERY: usize = 256;

type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type DoesSelectionFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type DecodeFn = unsafe extern "C" fn(
    *mut c_void,
    *mut OSSL_CORE_BIO,
    c_int,
    OSSL_CALLBACK,
    *mut c_void,
    OSSL_PASSPHRASE_CALLBACK,
    *mut c_void,
) -> c_int;
type ExportObjectFn =
    unsafe extern "C" fn(*mut c_void, *const c_void, usize, OSSL_CALLBACK, *mut c_void) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;

/// A decoder's context (`msblob2key_ctx_st` and `pvk2key_ctx_st`): its key type (DSA's or
/// RSA's), the properties (PVK's), and the selection of the last decoding.
struct BlobCtx {
    provctx: *mut c_void,
    propq: [c_char; MAX_PROPQUERY],
    dss: bool,
    selection: c_int,
}

impl BlobCtx {
    /// The key type's name.
    fn name(&self) -> &'static core::ffi::CStr {
        if self.dss { c"DSA" } else { c"RSA" }
    }

    /// Frees a key of the type.
    fn free(&self, key: *mut c_void) {
        if self.dss {
            // SAFETY: a DSA key made here, or NULL.
            unsafe { crate::dsa::DSA_free(key.cast()) };
        } else {
            // SAFETY: an RSA key made here, or NULL.
            unsafe { crate::rsa_lib::RSA_free(key.cast()) };
        }
    }

    /// `rsa_adjust`: an RSA key goes into the provider's library context (DSA's has no
    /// adjustment).
    fn adjust(&self, key: *mut c_void) {
        if !self.dss {
            // SAFETY: a live RSA key made here.
            if let Some(r) = unsafe { crate::rsa::rsa(key.cast()) } {
                // SAFETY: the provider's context, live while the provider is.
                r.libctx.set(unsafe { libctx_of(self.provctx) });
            }
        }
    }
}

fn newctx(provctx: *mut c_void, dss: bool) -> *mut c_void {
    Box::into_raw(Box::new(BlobCtx {
        provctx,
        propq: [0; MAX_PROPQUERY],
        dss,
        selection: 0,
    }))
    .cast()
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `newctx`.
unsafe fn bctx<'a>(vctx: *mut c_void) -> Option<&'a mut BlobCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { vctx.cast::<BlobCtx>().as_mut() }
}

ffi_callback! {
    /// `msblob2key_freectx` and `pvk2key_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context from `newctx` the caller gives up.
    pub(crate) unsafe extern "C" fn blob2key_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        if !vctx.is_null() {
            // SAFETY: the caller's guarantee.
            drop(unsafe { Box::from_raw(vctx.cast::<BlobCtx>()) });
        }
    }
}

ffi_callback! {
    /// `pvk2key_set_ctx_params`: the properties.
    ///
    /// # Safety
    /// `vctx` is a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn pvk2key_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { bctx(vctx) }) else { return 0 };
        // SAFETY: as above.
        c_int::from(unsafe { read_into(params, OSSL_DECODER_PARAM_PROPERTIES, &mut c.propq) })
    }
}

ffi_callback! {
    /// `msblob2key_does_selection`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn msblob_does_selection(_provctx: *mut c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        c_int::from(selection == 0 || selection & (OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    }
}

ffi_callback! {
    /// `pvk2key_does_selection`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn pvk_does_selection(_provctx: *mut c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        c_int::from(selection == 0 || selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0)
    }
}

/// Passes the key on by reference (freeing it after unless the callback took it): the
/// callback's result.
///
/// # Safety
/// `key` is NULL or a live key of the context's type; the callback takes its argument.
unsafe fn pass_on(
    c: &BlobCtx,
    mut key: *mut c_void,
    data_cb: OSSL_CALLBACK,
    data_cbarg: *mut c_void,
) -> c_int {
    if key.is_null() {
        return 1;
    }
    let mut object_type = OSSL_OBJECT_PKEY;
    let params = [
        // SAFETY: a static name; a local that outlives the call.
        unsafe { OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE.as_ptr(), &raw mut object_type) },
        // SAFETY: static strings.
        unsafe {
            OSSL_PARAM_construct_utf8_string(
                OSSL_OBJECT_PARAM_DATA_TYPE.as_ptr(),
                c.name().as_ptr().cast_mut(),
                0,
            )
        },
        // SAFETY: a static name; the key's pointer, a local the construct may take the key from.
        unsafe {
            OSSL_PARAM_construct_octet_string(
                OSSL_OBJECT_PARAM_REFERENCE.as_ptr(),
                (&raw mut key).cast(),
                size_of::<*mut c_void>(),
            )
        },
        // SAFETY: no preconditions.
        unsafe { OSSL_PARAM_construct_end() },
    ];
    let ok = match data_cb {
        // SAFETY: the decoding's callback with the parameters and its argument.
        Some(cb) => unsafe { cb(params.as_ptr(), data_cbarg) },
        None => 0,
    };
    c.free(key);
    ok
}

/// `msblob2key_decode`: the key of a blob of the context's type (the private key of a
/// private-key blob, the public key of a public-key one, as the selection allows), passed on;
/// success with nothing passed on for anything else.
///
/// # Safety
/// As for a decoder's `decode`.
unsafe fn msblob_decode(
    c: &mut BlobCtx,
    cin: *mut OSSL_CORE_BIO,
    selection: c_int,
    data_cb: OSSL_CALLBACK,
    data_cbarg: *mut c_void,
    pw_cb: OSSL_PASSPHRASE_CALLBACK,
    pw_cbarg: *mut c_void,
) -> c_int {
    const F: &str = "msblob2key_decode";
    // SAFETY: the caller's guarantee.
    let input = unsafe { bio_new_from_core_bio(cin) };
    if input.is_null() {
        return 0;
    }
    let mut key = ptr::null_mut::<c_void>();
    let ok = 'next: {
        // SAFETY: the BIO made above.
        let Some(hdr) = (unsafe { pvkfmt::read_exact(input, 16) }) else {
            err::raise(ERR_LIB_PEM, PEM_R_KEYBLOB_TOO_SHORT, F);
            break 'next 1;
        };
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        let (r, h) = pvkfmt::blob_header(&mut pvkfmt::Cursor(&hdr), 16, -1, -1);
        // SAFETY: as above.
        unsafe { ERR_pop_to_mark() };
        let Some(h) = h.filter(|_| r > 0) else {
            break 'next 1;
        };
        c.selection = selection;
        if h.isdss != c.dss {
            break 'next 1;
        }
        let length = pvkfmt::blob_length(h.bitlen, h.isdss, h.ispub);
        if length > pvkfmt::BLOB_MAX_LENGTH {
            err::raise(ERR_LIB_PEM, PEM_R_HEADER_TOO_LONG, F);
            break 'next 1;
        }
        // SAFETY: as above.
        let Some(buf) =
            (unsafe { pvkfmt::read_exact(input, usize::try_from(length).unwrap_or(0)) })
        else {
            err::raise(ERR_LIB_PEM, PEM_R_KEYBLOB_TOO_SHORT, F);
            break 'next 1;
        };
        let buf = rustyssl_crypto::bn::Zeroizing::new(buf);
        let read = |h: &pvkfmt::Header| -> *mut c_void {
            let mut cur = pvkfmt::Cursor(&buf);
            if h.isdss {
                pvkfmt::b2i_dsa_after_header(&mut cur, h.bitlen, h.ispub).cast()
            } else {
                pvkfmt::b2i_rsa_after_header(&mut cur, h.bitlen, h.ispub).cast()
            }
        };
        if (selection == 0 || selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0) && !h.ispub {
            // `ossl_pw_set_ossl_passphrase_cb`, for nothing: a blob isn't encrypted.
            if !PwData::default().set_ossl_passphrase_cb(pw_cb, pw_cbarg) {
                break 'next 0;
            }
            key = read(&h);
            if selection != 0 && key.is_null() {
                break 'next 1;
            }
        }
        if key.is_null()
            && (selection == 0 || selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY != 0)
            && h.ispub
        {
            key = read(&h);
            if selection != 0 && key.is_null() {
                break 'next 1;
            }
        }
        if !key.is_null() {
            c.adjust(key);
        }
        1
    };
    // SAFETY: made above.
    unsafe { crate::bio::BIO_free(input) };
    if ok == 0 {
        c.free(key);
        return 0;
    }
    // SAFETY: the key read above, or NULL; the caller's callback.
    unsafe { pass_on(c, key, data_cb, data_cbarg) }
}

/// `pvk2key_decode`: the key of a PVK of the context's type (decrypted with the passphrase the
/// callback gives), passed on; failure for a passphrase that can't be read or doesn't decrypt,
/// success with nothing passed on for anything else.
///
/// # Safety
/// As for a decoder's `decode`.
unsafe fn pvk_decode(
    c: &mut BlobCtx,
    cin: *mut OSSL_CORE_BIO,
    selection: c_int,
    data_cb: OSSL_CALLBACK,
    data_cbarg: *mut c_void,
    pw_cb: OSSL_PASSPHRASE_CALLBACK,
    pw_cbarg: *mut c_void,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let input = unsafe { bio_new_from_core_bio(cin) };
    if input.is_null() {
        return 0;
    }
    c.selection = selection;
    let mut key = ptr::null_mut::<c_void>();
    let ok = 'next: {
        if selection != 0 && selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY == 0 {
            break 'next 1;
        }
        let mut pwdata = PwData::default();
        if !pwdata.set_ossl_passphrase_cb(pw_cb, pw_cbarg) {
            break 'next 0;
        }
        // SAFETY: the provider's context, live while the provider is.
        let libctx = unsafe { libctx_of(c.provctx) };
        // SAFETY: the BIO made above; the password callback over the local data; the
        // properties.
        let (k, _) = unsafe {
            pvkfmt::pvk_key_bio(
                input,
                Some(pw_pvk_password),
                (&raw mut pwdata).cast(),
                c_int::from(c.dss),
                0,
                libctx,
                c.propq.as_ptr(),
            )
        };
        key = k;
        // A bad passphrase is fatal (the PVK API doesn't decrypt apart from reading).
        // SAFETY: no preconditions.
        let e = unsafe { ERR_peek_last_error() };
        if err::library_of(e) == ERR_LIB_PEM
            && matches!(
                err::reason_of(e),
                PEM_R_BAD_PASSWORD_READ | PEM_R_BAD_DECRYPT
            )
        {
            // SAFETY: as above.
            unsafe { ERR_clear_last_mark() };
            break 'next 0;
        }
        if selection != 0 && key.is_null() {
            break 'next 1;
        }
        if !key.is_null() {
            c.adjust(key);
        }
        1
    };
    // SAFETY: made above.
    unsafe { crate::bio::BIO_free(input) };
    if ok == 0 {
        c.free(key);
        return 0;
    }
    // SAFETY: the key read above, or NULL; the caller's callback.
    unsafe { pass_on(c, key, data_cb, data_cbarg) }
}

ffi_callback! {
    /// `msblob2key_export_object` and `pvk2key_export_object`: the referenced key's selected
    /// parts (all, for the last decoding's none) through its key manager's `export`.
    ///
    /// # Safety
    /// `reference` points to `reference_sz` octets; the callback takes its argument.
    pub(crate) unsafe extern "C" fn blob2key_export_object(vctx: *mut c_void, reference: *const c_void, reference_sz: usize, export_cb: OSSL_CALLBACK, export_cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { bctx(vctx) }) else { return 0 };
        if reference.is_null() || reference_sz != size_of::<*mut c_void>() {
            return 0;
        }
        let selection = if c.selection == 0 { OSSL_KEYMGMT_SELECT_ALL } else { c.selection };
        // SAFETY: the caller's guarantee: a key's pointer.
        let keydata = unsafe { reference.cast::<*mut c_void>().read_unaligned() };
        let export = if c.dss { dsa_export } else { rsa_export };
        // SAFETY: the key manager's export of its key.
        unsafe { export(keydata, selection, export_cb, export_cbarg) }
    }
}

/// An MSBLOB decoder's dispatch table.
macro_rules! msblob {
    ($table:ident, $newctx:ident, $decode:ident, $dss:expr) => {
        ffi_callback! {
            /// The decoder's `newctx`.
            ///
            /// # Safety
            /// `provctx` is the provider's context.
            pub(crate) unsafe extern "C" fn $newctx(provctx: *mut c_void) -> *mut c_void
            where failure = ptr::null_mut(), library = ERR_LIB_PROV
            {
                newctx(provctx, $dss)
            }
        }

        ffi_callback! {
            /// The decoder's `decode`.
            ///
            /// # Safety
            /// As for a decoder's `decode`.
            pub(crate) unsafe extern "C" fn $decode(vctx: *mut c_void, cin: *mut OSSL_CORE_BIO, selection: c_int, data_cb: OSSL_CALLBACK, data_cbarg: *mut c_void, pw_cb: OSSL_PASSPHRASE_CALLBACK, pw_cbarg: *mut c_void) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                let Some(c) = (unsafe { bctx(vctx) }) else { return 0 };
                // SAFETY: as above.
                unsafe { msblob_decode(c, cin, selection, data_cb, data_cbarg, pw_cb, pw_cbarg) }
            }
        }

        pub(super) static $table: Dispatch<6> = Dispatch([
            entry!(OSSL_FUNC_DECODER_NEWCTX, $newctx, NewCtxFn),
            entry!(OSSL_FUNC_DECODER_FREECTX, blob2key_freectx, FreeCtxFn),
            entry!(OSSL_FUNC_DECODER_DOES_SELECTION, msblob_does_selection, DoesSelectionFn),
            entry!(OSSL_FUNC_DECODER_DECODE, $decode, DecodeFn),
            entry!(OSSL_FUNC_DECODER_EXPORT_OBJECT, blob2key_export_object, ExportObjectFn),
            END,
        ]);
    };
}

/// A PVK decoder's dispatch table.
macro_rules! pvk {
    ($table:ident, $newctx:ident, $decode:ident, $dss:expr) => {
        ffi_callback! {
            /// The decoder's `newctx`.
            ///
            /// # Safety
            /// `provctx` is the provider's context.
            pub(crate) unsafe extern "C" fn $newctx(provctx: *mut c_void) -> *mut c_void
            where failure = ptr::null_mut(), library = ERR_LIB_PROV
            {
                newctx(provctx, $dss)
            }
        }

        ffi_callback! {
            /// The decoder's `decode`.
            ///
            /// # Safety
            /// As for a decoder's `decode`.
            pub(crate) unsafe extern "C" fn $decode(vctx: *mut c_void, cin: *mut OSSL_CORE_BIO, selection: c_int, data_cb: OSSL_CALLBACK, data_cbarg: *mut c_void, pw_cb: OSSL_PASSPHRASE_CALLBACK, pw_cbarg: *mut c_void) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                let Some(c) = (unsafe { bctx(vctx) }) else { return 0 };
                // SAFETY: as above.
                unsafe { pvk_decode(c, cin, selection, data_cb, data_cbarg, pw_cb, pw_cbarg) }
            }
        }

        pub(super) static $table: Dispatch<8> = Dispatch([
            entry!(OSSL_FUNC_DECODER_NEWCTX, $newctx, NewCtxFn),
            entry!(OSSL_FUNC_DECODER_FREECTX, blob2key_freectx, FreeCtxFn),
            entry!(OSSL_FUNC_DECODER_DOES_SELECTION, pvk_does_selection, DoesSelectionFn),
            entry!(OSSL_FUNC_DECODER_DECODE, $decode, DecodeFn),
            entry!(OSSL_FUNC_DECODER_EXPORT_OBJECT, blob2key_export_object, ExportObjectFn),
            entry!(OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, props_settable_ctx_params, ListFn),
            entry!(OSSL_FUNC_DECODER_SET_CTX_PARAMS, pvk2key_set_ctx_params, SetParamsFn),
            END,
        ]);
    };
}

msblob!(MSBLOB_DSA, msblob2dsa_newctx, msblob2dsa_decode, true);
msblob!(MSBLOB_RSA, msblob2rsa_newctx, msblob2rsa_decode, false);
pvk!(PVK_DSA, pvk2dsa_newctx, pvk2dsa_decode, true);
pvk!(PVK_RSA, pvk2rsa_newctx, pvk2rsa_decode, false);
