//! X.509's structures (`crypto/x509`, `crypto/asn1/x_*.c`), so far those the key encoders and
//! decoders need (step 4.7): the rest of AlgorithmIdentifier's functions, attributes,
//! `X509_SIG`, and PKCS#8's PrivateKeyInfo. Certificates and the rest come in phase 5.

pub(crate) mod algor;
pub(crate) mod attrib;
pub(crate) mod p8;
pub(crate) mod pbe;
pub(crate) mod pubkey;
pub(crate) mod sig;

#[cfg(test)]
mod tests {
    use core::ffi::c_int;
    use core::ptr;

    use super::algor::{X509_ALGOR_cmp, X509_ALGOR_get0, X509_ALGOR_set_md};
    use super::p8::{
        PKCS8_PRIV_KEY_INFO_free, PKCS8_PRIV_KEY_INFO_new, PKCS8_get_attr, PKCS8_pkey_add1_attr,
        PKCS8_pkey_add1_attr_by_NID, PKCS8_pkey_add1_attr_by_OBJ, PKCS8_pkey_get0,
        PKCS8_pkey_get0_attrs, PKCS8_pkey_set0,
    };
    use super::sig::{X509_SIG_get0, X509_SIG_getm};
    use crate::asn1::tpl::items::{X509_ALGOR_free, X509_ALGOR_new};

    /// docs/DEVIATIONS.md: the getters, comparisons, and setters OpenSSL reads or writes
    /// through NULL with do nothing or fail instead.
    #[test]
    fn null_arguments_are_safe() {
        let mut ptype: c_int = 7;
        // SAFETY: NULL where OpenSSL dereferences it; a local.
        unsafe {
            X509_ALGOR_get0(
                ptr::null_mut(),
                &raw mut ptype,
                ptr::null_mut(),
                ptr::null(),
            )
        };
        assert_eq!(ptype, 7);
        // SAFETY: no preconditions.
        let a = unsafe { X509_ALGOR_new() };
        // SAFETY: a live AlgorithmIdentifier; NULL for the digest.
        unsafe { X509_ALGOR_set_md(a, ptr::null()) };
        // SAFETY: NULL where OpenSSL dereferences it (here and below); a live
        // AlgorithmIdentifier.
        assert_eq!(unsafe { X509_ALGOR_cmp(ptr::null(), ptr::null()) }, 0);
        // SAFETY: as above.
        assert_ne!(unsafe { X509_ALGOR_cmp(a, ptr::null()) }, 0);
        // SAFETY: as above.
        assert_ne!(unsafe { X509_ALGOR_cmp(ptr::null(), a) }, 0);
        // SAFETY: made above.
        unsafe { X509_ALGOR_free(a) };
        // SAFETY: as above.
        unsafe { X509_SIG_get0(ptr::null(), ptr::null_mut(), ptr::null_mut()) };
        // SAFETY: as above.
        unsafe { X509_SIG_getm(ptr::null_mut(), ptr::null_mut(), ptr::null_mut()) };
        let (n, m) = (ptr::null_mut(), ptr::null_mut());
        // SAFETY: as above.
        let r = unsafe { PKCS8_pkey_get0(n, m, ptr::null_mut(), ptr::null_mut(), ptr::null()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        assert!(unsafe { PKCS8_pkey_get0_attrs(ptr::null()) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { PKCS8_get_attr(ptr::null_mut(), 0) }.is_null());
        let none = ptr::null_mut();
        // SAFETY: as above.
        let r = unsafe {
            PKCS8_pkey_set0(
                none,
                ptr::null_mut(),
                0,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            )
        };
        assert_eq!(r, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { PKCS8_pkey_add1_attr(none, ptr::null_mut()) }, 0);
        // SAFETY: as above.
        let r = unsafe { PKCS8_pkey_add1_attr_by_NID(none, 0, 0, ptr::null(), 0) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { PKCS8_pkey_add1_attr_by_OBJ(none, ptr::null(), 0, ptr::null(), 0) };
        assert_eq!(r, 0);
        // A key's octets without a place for their length: only the octets are written.
        // SAFETY: no preconditions.
        let p8 = unsafe { PKCS8_PRIV_KEY_INFO_new() };
        let mut pk: *const u8 = ptr::dangling();
        // SAFETY: a live PrivateKeyInfo; a local; NULL for the length.
        let r = unsafe {
            PKCS8_pkey_get0(
                ptr::null_mut(),
                &raw mut pk,
                ptr::null_mut(),
                ptr::null_mut(),
                p8,
            )
        };
        assert_eq!(r, 1);
        // SAFETY: made above.
        unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
