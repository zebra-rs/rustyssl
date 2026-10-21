//! PKCS#7 (`PKCS7`), for `pkcs7`, `smime`, and `pkcs12`.

use core::ffi::c_int;

use crate::abi::{NID_pkcs7_signed, NID_pkcs7_signedAndEnveloped, PKCS7};
use crate::bio::Bio;
use crate::ffi;
use crate::provider::LibCtx;
use crate::util::cstring;
use crate::x509::{Cert, Crl, certs_of, crls_of};

crate::handle!(
    /// An owned `PKCS7`.
    Pkcs7, PKCS7, PKCS7_free
);

/// What a `d2i`/`PEM_read` call with a reused object leaves: the result, else the object is
/// freed (if the call didn't already).
fn reused(result: *mut PKCS7, obj: *mut PKCS7) -> Option<Pkcs7> {
    if result.is_null() {
        // SAFETY: obj is NULL or the object, still owned here after the failed call.
        unsafe { ffi::PKCS7_free(obj) };
        return None;
    }
    Pkcs7::from_ptr(result)
}

impl Pkcs7 {
    /// Takes ownership of a `PKCS7` the caller got from the library.
    pub fn from_raw(p: *mut PKCS7) -> Option<Self> {
        Self::from_ptr(p)
    }

    /// `PKCS7_new_ex(libctx, propq)`.
    pub fn new_ex(libctx: Option<&LibCtx>, propq: Option<&str>) -> Option<Self> {
        let pq = match propq {
            Some(p) => Some(cstring(p)?),
            None => None,
        };
        // SAFETY: libctx is NULL or live; pq NULL or a valid C string.
        Self::from_ptr(unsafe {
            ffi::PKCS7_new_ex(
                libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr),
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            )
        })
    }

    /// `d2i_PKCS7_bio(bio, &self)`: the object filled in, or `None` (it is freed).
    pub fn read_der_into(self, bio: &Bio) -> Option<Self> {
        let mut p = self.into_ptr();
        // SAFETY: the BIO is live; p is an object the call may reuse or free.
        let r = unsafe { ffi::d2i_PKCS7_bio(bio.as_ptr(), &mut p) };
        reused(r, p)
    }

    /// `PEM_read_bio_PKCS7(bio, &self, NULL, NULL)`.
    pub fn read_pem_into(self, bio: &Bio) -> Option<Self> {
        let mut p = self.into_ptr();
        // SAFETY: as above; no callback.
        let r =
            unsafe { ffi::PEM_read_bio_PKCS7(bio.as_ptr(), &mut p, None, core::ptr::null_mut()) };
        reused(r, p)
    }

    /// `d2i_PKCS7_bio(bio, NULL)`.
    pub fn read_der(bio: &Bio) -> Option<Self> {
        // SAFETY: the BIO is live.
        Self::from_ptr(unsafe { ffi::d2i_PKCS7_bio(bio.as_ptr(), core::ptr::null_mut()) })
    }

    /// `PEM_read_bio_PKCS7(bio, NULL, NULL, NULL)`.
    pub fn read_pem(bio: &Bio) -> Option<Self> {
        // SAFETY: the BIO is live; no callback.
        Self::from_ptr(unsafe {
            ffi::PEM_read_bio_PKCS7(
                bio.as_ptr(),
                core::ptr::null_mut(),
                None,
                core::ptr::null_mut(),
            )
        })
    }

    /// `PKCS7_print_ctx(out, p7, indent, NULL)`.
    pub fn print_ctx(&self, out: &Bio, indent: c_int) -> c_int {
        // SAFETY: both are live; no print context.
        unsafe { ffi::PKCS7_print_ctx(out.as_ptr(), self.as_ptr(), indent, core::ptr::null()) }
    }

    /// `i2d_PKCS7_bio`.
    pub fn write_der(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::i2d_PKCS7_bio(out.as_ptr(), self.as_ptr()) }
    }

    /// `PEM_write_bio_PKCS7`.
    pub fn write_pem(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::PEM_write_bio_PKCS7(out.as_ptr(), self.as_ptr()) }
    }

    /// `OBJ_obj2nid(p7->type)`.
    pub fn type_nid(&self) -> c_int {
        // SAFETY: the object is live; its public layout has the type field.
        let t = unsafe { (*self.as_ptr()).type_ };
        // SAFETY: t is NULL or the object's live type.
        unsafe { ffi::OBJ_obj2nid(t) }
    }

    /// The certificates and CRLs of a signed or signed-and-enveloped object (`p7->d.sign`
    /// or `p7->d.signed_and_enveloped`), as `pkcs7 -print_certs` reads them: `None` for a
    /// stack that is absent.
    pub fn certs_and_crls(&self) -> (Option<Vec<Cert>>, Option<Vec<Crl>>) {
        let nid = self.type_nid();
        // SAFETY: the object is live.
        let d = unsafe { (*self.as_ptr()).d };
        let (certs, crls) = if nid == NID_pkcs7_signed {
            // SAFETY: the union member read is the one the type selects.
            let s = unsafe { d.sign };
            // SAFETY: s is NULL or the object's live signed content.
            match unsafe { s.as_ref() } {
                Some(s) => (s.cert, s.crl),
                None => (core::ptr::null_mut(), core::ptr::null_mut()),
            }
        } else if nid == NID_pkcs7_signedAndEnveloped {
            // SAFETY: as above.
            let s = unsafe { d.signed_and_enveloped };
            // SAFETY: as above.
            match unsafe { s.as_ref() } {
                Some(s) => (s.cert, s.crl),
                None => (core::ptr::null_mut(), core::ptr::null_mut()),
            }
        } else {
            (core::ptr::null_mut(), core::ptr::null_mut())
        };
        // The stacks are NULL or live, owned by the object.
        (
            (!certs.is_null()).then(|| certs_of(certs)),
            (!crls.is_null()).then(|| crls_of(crls)),
        )
    }
}
