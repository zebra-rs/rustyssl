//! `OSSL_ENCODER` and `OSSL_DECODER` contexts for keys.
//!
//! The commands call these functions with whatever the constructor returned, NULL included
//! (`OSSL_ENCODER_CTX_get_num_encoders(NULL)` is 0 and leaves an error), so a context here may
//! hold NULL, and every call passes it on as upstream does.

use core::ffi::c_int;

use crate::abi::{EVP_PKEY, OSSL_DECODER_CTX, OSSL_ENCODER_CTX};
use crate::bio::Bio;
use crate::ffi;
use crate::params::ParamList;
use crate::pkey::Pkey;
use crate::provider::LibCtx;
use crate::util::cstring;

/// A C string argument: `None` for NULL, or `Err` if the text holds a NUL.
fn opt_c(s: Option<&str>) -> Result<Option<std::ffi::CString>, ()> {
    match s {
        Some(s) => cstring(s).map(Some).ok_or(()),
        None => Ok(None),
    }
}

fn ptr_of(s: &Option<std::ffi::CString>) -> *const core::ffi::c_char {
    s.as_ref().map_or(core::ptr::null(), |c| c.as_ptr())
}

/// An `OSSL_ENCODER_CTX` (possibly NULL), freed when dropped.
pub struct Encoder(*mut OSSL_ENCODER_CTX);

impl Encoder {
    /// `OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, output_type, output_structure, NULL)`.
    pub fn new_for_pkey(
        pkey: &Pkey,
        selection: c_int,
        output_type: Option<&str>,
        output_structure: Option<&str>,
    ) -> Self {
        let (Ok(t), Ok(s)) = (opt_c(output_type), opt_c(output_structure)) else {
            return Self(core::ptr::null_mut());
        };
        // SAFETY: the key is live; the strings are valid or NULL for the call.
        Self(unsafe {
            ffi::OSSL_ENCODER_CTX_new_for_pkey(
                pkey.as_ptr(),
                selection,
                ptr_of(&t),
                ptr_of(&s),
                core::ptr::null(),
            )
        })
    }

    /// Whether the constructor returned NULL.
    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }

    /// `OSSL_ENCODER_CTX_get_num_encoders`.
    pub fn num_encoders(&self) -> c_int {
        // SAFETY: the context is NULL (which the function reports) or live.
        unsafe { ffi::OSSL_ENCODER_CTX_get_num_encoders(self.0) }
    }

    /// `OSSL_ENCODER_CTX_set_cipher(ctx, name, NULL)`.
    pub fn set_cipher(&self, name: Option<&str>) -> c_int {
        let Ok(n) = opt_c(name) else {
            return 0;
        };
        // SAFETY: as above; n is valid or NULL.
        unsafe { ffi::OSSL_ENCODER_CTX_set_cipher(self.0, ptr_of(&n), core::ptr::null()) }
    }

    /// `OSSL_ENCODER_CTX_set_passphrase_ui(ctx, get_ui_method(), NULL)`.
    pub fn set_passphrase_ui(&self) -> c_int {
        // SAFETY: as above; the method is the apps' (or NULL), live for the program.
        unsafe {
            ffi::OSSL_ENCODER_CTX_set_passphrase_ui(
                self.0,
                crate::ui::method(),
                core::ptr::null_mut(),
            )
        }
    }

    /// `OSSL_ENCODER_CTX_set_passphrase`.
    pub fn set_passphrase(&self, pass: &[u8]) -> c_int {
        // SAFETY: as above; pass is valid for its length (the library copies it).
        unsafe { ffi::OSSL_ENCODER_CTX_set_passphrase(self.0, pass.as_ptr(), pass.len()) }
    }

    /// `OSSL_ENCODER_CTX_set_params`.
    pub fn set_params(&self, params: &ParamList) -> c_int {
        // SAFETY: as above; params is a valid, ended array.
        unsafe { ffi::OSSL_ENCODER_CTX_set_params(self.0, params.as_ptr()) }
    }

    /// `OSSL_ENCODER_to_bio`.
    pub fn to_bio(&self, out: &Bio) -> c_int {
        // SAFETY: as above; the BIO is live.
        unsafe { ffi::OSSL_ENCODER_to_bio(self.0, out.as_ptr()) }
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        // SAFETY: NULL or owned by self, freed once here.
        unsafe { ffi::OSSL_ENCODER_CTX_free(self.0) };
    }
}

/// An `OSSL_DECODER_CTX` (possibly NULL) for one key, with the slot it decodes into.
pub struct Decoder {
    ctx: *mut OSSL_DECODER_CTX,
    slot: Box<*mut EVP_PKEY>,
}

impl Decoder {
    /// `OSSL_DECODER_CTX_new_for_pkey(&slot, input_type, input_structure, keytype,
    /// selection, libctx, propq)`.
    pub fn new_for_pkey(
        input_type: Option<&str>,
        input_structure: Option<&str>,
        keytype: Option<&str>,
        selection: c_int,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
    ) -> Self {
        let mut slot: Box<*mut EVP_PKEY> = Box::new(core::ptr::null_mut());
        let args = (
            opt_c(input_type),
            opt_c(input_structure),
            opt_c(keytype),
            opt_c(propq),
        );
        let (Ok(t), Ok(s), Ok(k), Ok(q)) = args else {
            return Self {
                ctx: core::ptr::null_mut(),
                slot,
            };
        };
        let lc = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: slot is a boxed out-pointer that lives as long as the context (both in
        // self); the strings are valid or NULL; lc is NULL or live.
        let ctx = unsafe {
            ffi::OSSL_DECODER_CTX_new_for_pkey(
                &mut *slot,
                ptr_of(&t),
                ptr_of(&s),
                ptr_of(&k),
                selection,
                lc,
                ptr_of(&q),
            )
        };
        Self { ctx, slot }
    }

    /// Whether the constructor returned NULL.
    pub fn is_null(&self) -> bool {
        self.ctx.is_null()
    }

    /// `OSSL_DECODER_from_bio`.
    pub fn from_bio(&self, input: &Bio) -> c_int {
        // SAFETY: the context is NULL (reported by the function) or live; the BIO is live.
        unsafe { ffi::OSSL_DECODER_from_bio(self.ctx, input.as_ptr()) }
    }

    /// The decoded key, if any.
    pub fn take(&mut self) -> Option<Pkey> {
        let p = core::mem::replace(&mut *self.slot, core::ptr::null_mut());
        Pkey::from_raw(p)
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        // SAFETY: NULL or owned by self, freed once here.
        unsafe { ffi::OSSL_DECODER_CTX_free(self.ctx) };
        // SAFETY: the key it decoded, if not taken (EVP_PKEY_free accepts NULL), freed once.
        unsafe { ffi::EVP_PKEY_free(*self.slot) };
    }
}
