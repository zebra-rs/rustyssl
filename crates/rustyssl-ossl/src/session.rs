//! TLS sessions (`SSL_SESSION`), for `sess_id`.

use core::ffi::{c_int, c_uint, c_void};

use crate::abi::{SSL_SESSION, d2i_of_void, i2d_of_void};
use crate::bio::Bio;
use crate::ffi;
use crate::load::Library;
use crate::util::c_function;
use crate::x509::Cert;

/// An owned `SSL_SESSION`.
pub struct Session(core::ptr::NonNull<SSL_SESSION>);

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: the session is owned by self and freed once, here.
        unsafe { ffi::SSL_SESSION_free(self.0.as_ptr()) };
    }
}

impl Session {
    fn from_ptr(p: *mut SSL_SESSION) -> Option<Self> {
        core::ptr::NonNull::new(p).map(Self)
    }

    pub fn as_ptr(&self) -> *mut SSL_SESSION {
        self.0.as_ptr()
    }

    /// `d2i_SSL_SESSION_bio(bio, NULL)` (the macro over `ASN1_d2i_bio`).
    pub fn read_der(bio: &Bio) -> Option<Self> {
        let xnew = c_function(Library::Ssl, "SSL_SESSION_new\0");
        let d2i = c_function(Library::Ssl, "d2i_SSL_SESSION\0");
        // SAFETY: the addresses are the exports SSL_SESSION_new (void *(*)(void)) and
        // d2i_SSL_SESSION, whose prototype d2i_of_void matches up to the object pointer type,
        // exactly as the C macro casts them.
        let xnew = unsafe {
            core::mem::transmute::<*mut c_void, unsafe extern "C" fn() -> *mut c_void>(xnew)
        };
        // SAFETY: as above.
        let d2i = unsafe { core::mem::transmute::<*mut c_void, d2i_of_void>(d2i) };
        // SAFETY: the BIO is live; no object to reuse.
        let p = unsafe { ffi::ASN1_d2i_bio(Some(xnew), d2i, bio.as_ptr(), core::ptr::null_mut()) };
        Self::from_ptr(p.cast())
    }

    /// `PEM_read_bio_SSL_SESSION(bio, NULL, NULL, NULL)`.
    pub fn read_pem(bio: &Bio) -> Option<Self> {
        // SAFETY: the BIO is live; no callback.
        Self::from_ptr(unsafe {
            ffi::PEM_read_bio_SSL_SESSION(
                bio.as_ptr(),
                core::ptr::null_mut(),
                None,
                core::ptr::null_mut(),
            )
        })
    }

    /// `SSL_SESSION_get0_peer`, as a new reference.
    pub fn peer(&self) -> Option<Cert> {
        // SAFETY: the session is live; the certificate is owned by it.
        Cert::from_borrowed(unsafe { ffi::SSL_SESSION_get0_peer(self.as_ptr()) })
    }

    /// `SSL_SESSION_set1_id_context`.
    pub fn set1_id_context(&self, ctx: &[u8]) -> bool {
        let Ok(n) = c_uint::try_from(ctx.len()) else {
            return false;
        };
        // SAFETY: the session is live; ctx is valid for n bytes.
        unsafe { ffi::SSL_SESSION_set1_id_context(self.as_ptr(), ctx.as_ptr(), n) == 1 }
    }

    /// `SSL_SESSION_print`.
    pub fn print(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::SSL_SESSION_print(out.as_ptr(), self.as_ptr()) }
    }

    /// `SSL_SESSION_print_keylog`.
    pub fn print_keylog(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::SSL_SESSION_print_keylog(out.as_ptr(), self.as_ptr()) }
    }

    /// `PEM_write_bio_SSL_SESSION`.
    pub fn write_pem(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::PEM_write_bio_SSL_SESSION(out.as_ptr(), self.as_ptr()) }
    }

    /// `i2d_SSL_SESSION_bio` (the macro over `ASN1_i2d_bio`).
    pub fn write_der(&self, out: &Bio) -> c_int {
        let i2d = c_function(Library::Ssl, "i2d_SSL_SESSION\0");
        // SAFETY: the address is the export i2d_SSL_SESSION, whose prototype i2d_of_void
        // matches up to the object pointer type, as the C macro casts it.
        let i2d = unsafe { core::mem::transmute::<*mut c_void, i2d_of_void>(i2d) };
        // SAFETY: both are live.
        unsafe { ffi::ASN1_i2d_bio(i2d, out.as_ptr(), self.as_ptr().cast()) }
    }
}
