//! Netscape's signed public keys and certificate sequences (`x_spki.c`, `x509spki.c`,
//! `t_spki.c`, `nsseq.c`, and the SPKI parts of `x_all.c`): `NETSCAPE_SPKI` (a key and
//! challenge, `SignedPublicKeyAndChallenge`, as browsers' `<keygen>` made), with its base64
//! form, signing, verification, and printing; and `NETSCAPE_CERT_SEQUENCE`.
//!
//! As OpenSSL's, the base64 form is the DER as one unbroken line, and a new certificate
//! sequence has the type `netscape-cert-sequence`.

use core::ffi::{c_char, c_int, c_void};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_OBJECT, ASN1_OP_NEW_POST, ASN1_TFLG_EMBED, ASN1_TFLG_EXPLICIT,
    ASN1_TFLG_OPTIONAL, ASN1_TFLG_SEQUENCE_OF, ASN1_VALUE, BIO, ERR_LIB_ASN1, ERR_LIB_X509, EVP_MD,
    EVP_PKEY, NETSCAPE_CERT_SEQUENCE, NETSCAPE_SPKAC, NETSCAPE_SPKI, NID_netscape_cert_sequence,
    NID_undef, X509_R_BASE64_DECODE_ERROR,
};

use super::cert::X509_it;
use super::pubkey::{X509_PUBKEY_get, X509_PUBKEY_get0_param, X509_PUBKEY_it, X509_PUBKEY_set};
use crate::asn1::sign::{ASN1_item_sign_ex, ASN1_item_verify};
use crate::asn1::tpl::items::{
    ASN1_BIT_STRING_it, ASN1_IA5STRING_it, ASN1_OBJECT_it, X509_ALGOR_it, d2i, i2d, new_free,
};
use crate::asn1::tpl::statics::{Aux, Templates, aux, sequence};
use crate::asn1::tpl::{item_fns, template_at};
use crate::bio::BIO_write;
use crate::bio::print::BIO_printf;
use crate::err;
use crate::evp::encode::{EVP_DecodeBlock, EVP_EncodeBlock};
use crate::evp::pkey::EVP_PKEY_free;
use crate::evp::pkey::print::EVP_PKEY_print_public;
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::objects::{OBJ_nid2ln, OBJ_nid2obj, OBJ_obj2nid};

static SPKAC_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(NETSCAPE_SPKAC, pubkey),
        c"pubkey",
        X509_PUBKEY_it,
    ),
    template_at(
        0,
        0,
        offset_of!(NETSCAPE_SPKAC, challenge),
        c"challenge",
        ASN1_IA5STRING_it,
    ),
]);

item_fns! {
    /// PublicKeyAndChallenge: SEQUENCE { spki SubjectPublicKeyInfo, challenge IA5String }.
    pub unsafe extern "C" fn NETSCAPE_SPKAC_it = sequence::<NETSCAPE_SPKAC, 2>(&SPKAC_TT, None, c"NETSCAPE_SPKAC");
}

new_free! {
    pub unsafe extern "C" fn NETSCAPE_SPKAC_new, pub unsafe extern "C" fn NETSCAPE_SPKAC_free(NETSCAPE_SPKAC) = NETSCAPE_SPKAC_it;
}

i2d! {
    /// Encodes a PublicKeyAndChallenge.
    pub unsafe extern "C" fn i2d_NETSCAPE_SPKAC(NETSCAPE_SPKAC) = NETSCAPE_SPKAC_it;
}

d2i! {
    /// Decodes a PublicKeyAndChallenge (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_NETSCAPE_SPKAC(NETSCAPE_SPKAC) = NETSCAPE_SPKAC_it;
}

static SPKI_TT: Templates<3> = Templates([
    template_at(
        0,
        0,
        offset_of!(NETSCAPE_SPKI, spkac),
        c"spkac",
        NETSCAPE_SPKAC_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(NETSCAPE_SPKI, sig_algor),
        c"sig_algor",
        X509_ALGOR_it,
    ),
    template_at(
        0,
        0,
        offset_of!(NETSCAPE_SPKI, signature),
        c"signature",
        ASN1_BIT_STRING_it,
    ),
]);

item_fns! {
    /// SignedPublicKeyAndChallenge: SEQUENCE { publicKeyAndChallenge, signatureAlgorithm,
    /// signature }.
    pub unsafe extern "C" fn NETSCAPE_SPKI_it = sequence::<NETSCAPE_SPKI, 3>(&SPKI_TT, None, c"NETSCAPE_SPKI");
}

new_free! {
    pub unsafe extern "C" fn NETSCAPE_SPKI_new, pub unsafe extern "C" fn NETSCAPE_SPKI_free(NETSCAPE_SPKI) = NETSCAPE_SPKI_it;
}

i2d! {
    /// Encodes a SignedPublicKeyAndChallenge.
    pub unsafe extern "C" fn i2d_NETSCAPE_SPKI(NETSCAPE_SPKI) = NETSCAPE_SPKI_it;
}

d2i! {
    /// Decodes a SignedPublicKeyAndChallenge (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_NETSCAPE_SPKI(NETSCAPE_SPKI) = NETSCAPE_SPKI_it;
}

/// The SPKI's PublicKeyAndChallenge, or `None`.
///
/// # Safety
/// `x` is NULL or a live SPKI.
unsafe fn spkac_of<'a>(x: *const NETSCAPE_SPKI) -> Option<&'a mut NETSCAPE_SPKAC> {
    // SAFETY: the caller's guarantee; its PublicKeyAndChallenge, or NULL.
    unsafe { x.as_ref() }.and_then(|s| unsafe { s.spkac.as_mut() })
}

ffi_export! {
    /// Sets the SPKI's public key to `pkey`'s: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live SPKI; `pkey` is NULL or a live key.
    pub unsafe extern "C" fn NETSCAPE_SPKI_set_pubkey(x: *mut NETSCAPE_SPKI, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { spkac_of(x) }) else { return 0 };
        // SAFETY: its slot; the caller's key.
        unsafe { X509_PUBKEY_set(&raw mut s.pubkey, pkey) }
    }
}

ffi_export! {
    /// The SPKI's public key with a reference for the caller, or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live SPKI.
    pub unsafe extern "C" fn NETSCAPE_SPKI_get_pubkey(x: *mut NETSCAPE_SPKI) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { spkac_of(x) }) else { return ptr::null_mut() };
        // SAFETY: its SubjectPublicKeyInfo.
        unsafe { X509_PUBKEY_get(s.pubkey) }
    }
}

ffi_export! {
    /// The SPKI the base64 text (`len` octets, or up to its NUL for 0 or less) encodes, or NULL
    /// (`X509_R_BASE64_DECODE_ERROR` for bad base64).
    ///
    /// # Safety
    /// `str` holds `len` octets, or is a C string for 0 or less.
    pub unsafe extern "C" fn NETSCAPE_SPKI_b64_decode(str: *const c_char, len: c_int) -> *mut NETSCAPE_SPKI
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        if str.is_null() {
            return ptr::null_mut();
        }
        let len = if len <= 0 {
            // SAFETY: the caller's guarantee.
            c_int::try_from(unsafe { core::ffi::CStr::from_ptr(str) }.count_bytes()).unwrap_or(c_int::MAX)
        } else {
            len
        };
        let Some(size) = usize::try_from(len).ok().and_then(|n| n.checked_add(1)) else { return ptr::null_mut() };
        let der = mem::alloc(size).cast::<u8>();
        if der.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: room for the decoding (at most `len` octets); the caller's text.
        let n = unsafe { EVP_DecodeBlock(der, str.cast(), len) };
        if n < 0 {
            err::raise(ERR_LIB_X509, X509_R_BASE64_DECODE_ERROR, "NETSCAPE_SPKI_b64_decode");
            // SAFETY: made above.
            unsafe { mem::release(der.cast()) };
            return ptr::null_mut();
        }
        let mut p = der.cast_const();
        // SAFETY: the decoding's `n` octets.
        let spki = unsafe { d2i_NETSCAPE_SPKI(ptr::null_mut(), &raw mut p, core::ffi::c_long::from(n)) };
        // SAFETY: made above.
        unsafe { mem::release(der.cast()) };
        spki
    }
}

ffi_export! {
    /// The SPKI's DER in base64, one line, for the caller to free; NULL on failure.
    ///
    /// # Safety
    /// `spki` is NULL or a live SPKI.
    pub unsafe extern "C" fn NETSCAPE_SPKI_b64_encode(spki: *mut NETSCAPE_SPKI) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let der_len = unsafe { i2d_NETSCAPE_SPKI(spki, ptr::null_mut()) };
        let Ok(n) = usize::try_from(der_len) else { return ptr::null_mut() };
        if n == 0 {
            return ptr::null_mut();
        }
        // Room for the base64 and its NUL (OpenSSL allocates twice the DER, which a SPKI
        // always fills less than).
        let b64_size = n.div_ceil(3).saturating_mul(4).saturating_add(1).max(n.saturating_mul(2));
        let der = mem::alloc(n).cast::<u8>();
        let b64 = mem::alloc(b64_size).cast::<u8>();
        if der.is_null() || b64.is_null() {
            // SAFETY: made above, or NULL.
            unsafe { mem::release(der.cast()) };
            // SAFETY: as above.
            unsafe { mem::release(b64.cast()) };
            return ptr::null_mut();
        }
        let mut p = der;
        // SAFETY: as above; room for the DER.
        unsafe { i2d_NETSCAPE_SPKI(spki, &raw mut p) };
        // SAFETY: room for the base64; the DER.
        unsafe { EVP_EncodeBlock(b64, der, der_len) };
        // SAFETY: made above.
        unsafe { mem::release(der.cast()) };
        b64.cast()
    }
}

ffi_export! {
    /// Checks the SPKI's signature with `r`: 1, 0, or -1.
    ///
    /// # Safety
    /// `a` is NULL or a live SPKI; `r` is NULL or a live key.
    pub unsafe extern "C" fn NETSCAPE_SPKI_verify(a: *mut NETSCAPE_SPKI, r: *mut EVP_PKEY) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { a.as_ref() }) else { return -1 };
        // SAFETY: no preconditions.
        let it = unsafe { NETSCAPE_SPKAC_it() };
        // SAFETY: the SPKI's PublicKeyAndChallenge, algorithm, and signature; the caller's key.
        unsafe { ASN1_item_verify(it, &raw const s.sig_algor, s.signature, s.spkac.cast(), r) }
    }
}

ffi_export! {
    /// Signs the SPKI with `pkey` and `md`: the signature's length, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live SPKI; `pkey` is a live key; `md` is NULL or a digest.
    pub unsafe extern "C" fn NETSCAPE_SPKI_sign(x: *mut NETSCAPE_SPKI, pkey: *mut EVP_PKEY, md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { x.as_mut() }) else { return 0 };
        // SAFETY: no preconditions.
        let it = unsafe { NETSCAPE_SPKAC_it() };
        // SAFETY: the SPKI's fields; the caller's key and digest.
        unsafe {
            ASN1_item_sign_ex(it, &raw mut s.sig_algor, ptr::null_mut(), s.signature, s.spkac.cast(), ptr::null(), pkey, md, ptr::null_mut(), ptr::null())
        }
    }
}

/// A NID's long name, or `UNKNOWN` for `NID_undef`.
fn long_name(nid: c_int) -> *const c_char {
    if nid == NID_undef {
        return c"UNKNOWN".as_ptr();
    }
    // SAFETY: no preconditions.
    unsafe { OBJ_nid2ln(nid) }
}

ffi_export! {
    /// Prints the SPKI: its key's algorithm and the key, the challenge, and the signature
    /// algorithm and value. 1.
    ///
    /// # Safety
    /// `out` is a live BIO; `spki` is a live SPKI.
    pub unsafe extern "C" fn NETSCAPE_SPKI_print(out: *mut BIO, spki: *mut NETSCAPE_SPKI) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { spki.as_ref() }) else { return 0 };
        // SAFETY: as above.
        let Some(ac) = (unsafe { s.spkac.as_ref() }) else { return 0 };
        // SAFETY: the caller's BIO; a static format.
        unsafe { BIO_printf(out, c"Netscape SPKI:\n".as_ptr()) };
        let mut oid: *mut ASN1_OBJECT = ptr::null_mut();
        let n = ptr::null_mut();
        // SAFETY: its SubjectPublicKeyInfo; a local.
        unsafe { X509_PUBKEY_get0_param(&raw mut oid, n, n.cast(), n.cast(), ac.pubkey) };
        // SAFETY: the algorithm, or NULL.
        let nid = unsafe { OBJ_obj2nid(oid) };
        // SAFETY: as above; a static format and its argument.
        unsafe { BIO_printf(out, c"  Public Key Algorithm: %s\n".as_ptr(), long_name(nid)) };
        // SAFETY: as above.
        let pkey = unsafe { X509_PUBKEY_get(ac.pubkey) };
        if pkey.is_null() {
            // SAFETY: as above.
            unsafe { BIO_printf(out, c"  Unable to load public key\n".as_ptr()) };
        } else {
            // SAFETY: as above; the key.
            unsafe { EVP_PKEY_print_public(out, pkey, 4, ptr::null_mut()) };
            // SAFETY: the reference taken above.
            unsafe { EVP_PKEY_free(pkey) };
        }
        // SAFETY: its challenge.
        if let Some(chal) = unsafe { ac.challenge.as_ref() }
            && chal.length != 0
        {
            // SAFETY: as above; a static format and its arguments.
            unsafe { BIO_printf(out, c"  Challenge String: %.*s\n".as_ptr(), chal.length, chal.data) };
        }
        // SAFETY: its signature algorithm.
        let nid = unsafe { OBJ_obj2nid(s.sig_algor.algorithm) };
        // SAFETY: as above.
        unsafe { BIO_printf(out, c"  Signature Algorithm: %s".as_ptr(), long_name(nid)) };
        // SAFETY: its signature, or NULL.
        if let Some(sig) = unsafe { s.signature.as_ref() } {
            let n = usize::try_from(sig.length).unwrap_or(0);
            let data = if n == 0 || sig.data.is_null() {
                &[][..]
            } else {
                // SAFETY: a string's data holds its length.
                unsafe { core::slice::from_raw_parts(sig.data, n) }
            };
            let mut text = Vec::new();
            for (i, b) in data.iter().enumerate() {
                if i % 18 == 0 {
                    text.extend_from_slice(b"\n      ");
                }
                text.extend_from_slice(format!("{b:02x}").as_bytes());
                if i + 1 != n {
                    text.push(b':');
                }
            }
            text.push(b'\n');
            let len = c_int::try_from(text.len()).unwrap_or(c_int::MAX);
            // SAFETY: as above; the text.
            unsafe { BIO_write(out, text.as_ptr().cast(), len) };
        }
        1
    }
}

// The certificate sequence (`nsseq.c`).

ffi_callback! {
    /// `nsseq_cb`: a new sequence has the type `netscape-cert-sequence`.
    ///
    /// # Safety
    /// `pval` holds NULL or a live sequence.
    pub(crate) unsafe extern "C" fn nsseq_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, _exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if operation == ASN1_OP_NEW_POST {
            // SAFETY: the caller's guarantee.
            let v = unsafe { pval.read() };
            // SAFETY: as above.
            if let Some(s) = unsafe { v.cast::<NETSCAPE_CERT_SEQUENCE>().as_mut() } {
                // SAFETY: no preconditions.
                s.type_ = unsafe { OBJ_nid2obj(NID_netscape_cert_sequence) };
            }
        }
        1
    }
}

static NSSEQ_AUX: Aux = aux(nsseq_cb);

static NSSEQ_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(NETSCAPE_CERT_SEQUENCE, type_),
        c"type",
        ASN1_OBJECT_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(NETSCAPE_CERT_SEQUENCE, certs),
        c"certs",
        X509_it,
    ),
]);

item_fns! {
    /// NetscapeCertSequence: SEQUENCE { type OBJECT IDENTIFIER, certs [0] EXPLICIT SEQUENCE OF
    /// Certificate OPTIONAL }.
    pub unsafe extern "C" fn NETSCAPE_CERT_SEQUENCE_it = sequence::<NETSCAPE_CERT_SEQUENCE, 2>(&NSSEQ_TT, Some(&NSSEQ_AUX), c"NETSCAPE_CERT_SEQUENCE");
}

new_free! {
    pub unsafe extern "C" fn NETSCAPE_CERT_SEQUENCE_new, pub unsafe extern "C" fn NETSCAPE_CERT_SEQUENCE_free(NETSCAPE_CERT_SEQUENCE) = NETSCAPE_CERT_SEQUENCE_it;
}

i2d! {
    /// Encodes a certificate sequence.
    pub unsafe extern "C" fn i2d_NETSCAPE_CERT_SEQUENCE(NETSCAPE_CERT_SEQUENCE) = NETSCAPE_CERT_SEQUENCE_it;
}

d2i! {
    /// Decodes a certificate sequence (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_NETSCAPE_CERT_SEQUENCE(NETSCAPE_CERT_SEQUENCE) = NETSCAPE_CERT_SEQUENCE_it;
}
