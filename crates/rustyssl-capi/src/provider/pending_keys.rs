//! Placeholders for the key decoders still to come: MSBLOB's and PVK's (`decode_msblob2key.c`,
//! `decode_pvk2key.c`, step 4.7e).
//!
//! Each selects what OpenSSL's does and reads its input as far as telling whether it's of its
//! kind (raising OpenSSL's errors on the way): input of another kind is passed over, as
//! OpenSSL's decoders pass it over, and input of its kind aborts (AGENTS.md rule 10), since
//! OpenSSL's would decode it.

use core::ffi::{c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PEM, ERR_LIB_PROV, OSSL_CALLBACK, OSSL_CORE_BIO, OSSL_FUNC_DECODER_DECODE,
    OSSL_FUNC_DECODER_DOES_SELECTION, OSSL_FUNC_DECODER_FREECTX, OSSL_FUNC_DECODER_NEWCTX,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_PASSPHRASE_CALLBACK,
    PEM_R_BAD_MAGIC_NUMBER, PEM_R_EXPECTING_DSS_KEY_BLOB, PEM_R_EXPECTING_RSA_KEY_BLOB,
    PEM_R_INCONSISTENT_HEADER, PEM_R_KEYBLOB_TOO_SHORT, PEM_R_PVK_DATA_TOO_SHORT,
    PEM_R_UNSUPPORTED_PVK_KEY_TYPE,
};

use super::tables::{Dispatch, END, entry};
use crate::decoder::ctx::bio_new_from_core_bio;
use crate::err;
use crate::ffi::ffi_callback;

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

ffi_callback! {
    /// The placeholders' `newctx`: nothing to keep (a non-NULL token).
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn pending_newctx(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        let _ = provctx;
        ptr::dangling_mut()
    }
}

ffi_callback! {
    /// The placeholders' `freectx`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn pending_freectx(_vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {}
}

// MSBLOB and PVK (`pvkfmt.c`'s format constants).
const MS_PUBLICKEYBLOB: u8 = 0x6;
const MS_PRIVATEKEYBLOB: u8 = 0x7;
const MS_RSA1MAGIC: u32 = 0x3141_5352;
const MS_RSA2MAGIC: u32 = 0x3241_5352;
const MS_DSS1MAGIC: u32 = 0x3153_5344;
const MS_DSS2MAGIC: u32 = 0x3253_5344;
const MS_KEYTYPE_KEYX: u32 = 0x1;
const MS_KEYTYPE_SIGN: u32 = 0x2;
const MS_PVKMAGIC: u32 = 0xb0b5_f11e;
const PVK_MAX_KEYLEN: u32 = 102_400;
const PVK_MAX_SALTLEN: u32 = 10240;

/// Reads up to `n` octets from the core BIO, or `None` when it can't be read.
///
/// # Safety
/// `cin` is a live core BIO.
unsafe fn read_head(cin: *mut OSSL_CORE_BIO, n: usize) -> Option<Vec<u8>> {
    // SAFETY: the caller's guarantee.
    let bio = unsafe { bio_new_from_core_bio(cin) };
    if bio.is_null() {
        return None;
    }
    let mut buf = vec![0u8; n];
    let want = c_int::try_from(n).unwrap_or(0);
    // SAFETY: the new BIO; room for `n` octets.
    let got = unsafe { crate::bio::BIO_read(bio, buf.as_mut_ptr().cast(), want) };
    // SAFETY: made above.
    unsafe { crate::bio::BIO_free(bio) };
    buf.truncate(usize::try_from(got).unwrap_or(0));
    Some(buf)
}

/// The little-endian 32-bit word at `at`.
fn ledword(b: &[u8], at: usize) -> u32 {
    let mut w = [0u8; 4];
    if let Some(s) = b.get(at..at + 4) {
        w.copy_from_slice(s);
    }
    u32::from_le_bytes(w)
}

/// `ossl_do_blob_header` with neither kind nor type expected: whether a 16-octet header is a
/// key blob's, and whether it's DSS's.
fn blob_header(h: &[u8]) -> Option<bool> {
    let ispub = match *h.first()? {
        MS_PUBLICKEYBLOB => true,
        MS_PRIVATEKEYBLOB => false,
        _ => return None,
    };
    if h.get(1) != Some(&0x2) {
        return None;
    }
    match (ledword(h, 8), ispub) {
        (MS_RSA1MAGIC, true) | (MS_RSA2MAGIC, false) => Some(false),
        (MS_DSS1MAGIC, true) | (MS_DSS2MAGIC, false) => Some(true),
        _ => None,
    }
}

/// An MSBLOB placeholder's `decode`: aborts for a key blob of its type (`dss`).
///
/// # Safety
/// As for a decoder's `decode`.
unsafe fn msblob_decode(cin: *mut OSSL_CORE_BIO, dss: bool) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(h) = (unsafe { read_head(cin, 16) }) else {
        return 0;
    };
    if h.len() != 16 {
        err::raise(ERR_LIB_PEM, PEM_R_KEYBLOB_TOO_SHORT, "msblob2key_decode");
        return 1;
    }
    if blob_header(&h) == Some(dss) {
        crate::stub::unimplemented("decoding an MSBLOB key (step 4.7e)");
    }
    1
}

/// A PVK placeholder's `decode` (its selection asking for the private key): `ossl_do_PVK_header`'s
/// checks and errors, then aborts for a PVK of its type (`dss`).
///
/// # Safety
/// As for a decoder's `decode`.
unsafe fn pvk_decode(cin: *mut OSSL_CORE_BIO, selection: c_int, dss: bool) -> c_int {
    if selection != 0 && selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY == 0 {
        return 1;
    }
    // SAFETY: the caller's guarantee.
    let Some(h) = (unsafe { read_head(cin, 24) }) else {
        return 0;
    };
    const F: &str = "ossl_do_PVK_header";
    if h.len() != 24 {
        err::raise(ERR_LIB_PEM, PEM_R_PVK_DATA_TOO_SHORT, "do_PVK_key_bio");
        return 1;
    }
    if ledword(&h, 0) != MS_PVKMAGIC {
        err::raise(ERR_LIB_PEM, PEM_R_BAD_MAGIC_NUMBER, F);
        return 1;
    }
    match ledword(&h, 8) {
        MS_KEYTYPE_KEYX if dss => {
            err::raise(ERR_LIB_PEM, PEM_R_EXPECTING_RSA_KEY_BLOB, F);
            return 1;
        }
        MS_KEYTYPE_SIGN if !dss => {
            err::raise(ERR_LIB_PEM, PEM_R_EXPECTING_DSS_KEY_BLOB, F);
            return 1;
        }
        MS_KEYTYPE_KEYX | MS_KEYTYPE_SIGN => {}
        _ => {
            err::raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_PVK_KEY_TYPE, F);
            return 1;
        }
    }
    let (encrypted, saltlen, keylen) = (ledword(&h, 12), ledword(&h, 16), ledword(&h, 20));
    if keylen > PVK_MAX_KEYLEN || saltlen > PVK_MAX_SALTLEN {
        return 1;
    }
    if encrypted != 0 && saltlen == 0 {
        err::raise(ERR_LIB_PEM, PEM_R_INCONSISTENT_HEADER, F);
        return 1;
    }
    crate::stub::unimplemented("decoding a PVK key (step 4.7e)")
}

ffi_callback! {
    /// The MSBLOB placeholders' `does_selection` (`msblob2key_does_selection`).
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
    /// The PVK placeholders' `does_selection` (`pvk2key_does_selection`).
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn pvk_does_selection(_provctx: *mut c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        c_int::from(selection == 0 || selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0)
    }
}

/// An MSBLOB or PVK placeholder's dispatch table.
macro_rules! blob_placeholder {
    ($table:ident, $decode:ident, $does:ident, $f:ident, $dss:expr) => {
        ffi_callback! {
            /// The placeholder's `decode`.
            ///
            /// # Safety
            /// As for a decoder's `decode`.
            pub(crate) unsafe extern "C" fn $decode(_vctx: *mut c_void, cin: *mut OSSL_CORE_BIO, selection: c_int, _data_cb: OSSL_CALLBACK, _data_cbarg: *mut c_void, _pw_cb: OSSL_PASSPHRASE_CALLBACK, _pw_cbarg: *mut c_void) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { $f(cin, selection, $dss) }
            }
        }

        pub(super) static $table: Dispatch<5> = Dispatch([
            entry!(OSSL_FUNC_DECODER_NEWCTX, pending_newctx, NewCtxFn),
            entry!(OSSL_FUNC_DECODER_FREECTX, pending_freectx, FreeCtxFn),
            entry!(OSSL_FUNC_DECODER_DOES_SELECTION, $does, DoesSelectionFn),
            entry!(OSSL_FUNC_DECODER_DECODE, $decode, DecodeFn),
            END,
        ]);
    };
}

/// `msblob_decode` with the selection the PVK form takes.
///
/// # Safety
/// As for `msblob_decode`.
unsafe fn msblob(cin: *mut OSSL_CORE_BIO, _selection: c_int, dss: bool) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { msblob_decode(cin, dss) }
}

blob_placeholder!(
    MSBLOB_DSA,
    msblob_dsa_decode,
    msblob_does_selection,
    msblob,
    true
);
blob_placeholder!(
    MSBLOB_RSA,
    msblob_rsa_decode,
    msblob_does_selection,
    msblob,
    false
);
blob_placeholder!(
    PVK_DSA,
    pvk_dsa_decode,
    pvk_does_selection,
    pvk_decode,
    true
);
blob_placeholder!(
    PVK_RSA,
    pvk_rsa_decode,
    pvk_does_selection,
    pvk_decode,
    false
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_headers_are_told_apart() {
        let mut h = [0u8; 16];
        h[0] = MS_PRIVATEKEYBLOB;
        h[1] = 2;
        h[8..12].copy_from_slice(&MS_RSA2MAGIC.to_le_bytes());
        assert_eq!(blob_header(&h), Some(false));
        h[8..12].copy_from_slice(&MS_DSS2MAGIC.to_le_bytes());
        assert_eq!(blob_header(&h), Some(true));
        h[8..12].copy_from_slice(&MS_DSS1MAGIC.to_le_bytes());
        assert_eq!(blob_header(&h), None);
        h[0] = 0x30;
        assert_eq!(blob_header(&h), None);
    }
}
