//! PKCS #12's structures and their ASN.1 (`p12_asn.c`, `p12_utl.c`'s I/O): PFX, MacData,
//! SafeBag and its bags, SafeContents, and AuthenticatedSafe.
//!
//! The structures are opaque in `pkcs12.h`; their layouts here are OpenSSL's internal ones
//! (`p12_local.h`), which the templates describe.

use core::ffi::{c_int, c_void};

use core::mem::offset_of;
use core::ptr;
use libc::FILE;

use rustyssl_abi::{
    ASN1_INTEGER, ASN1_ITEM, ASN1_ITYPE_PRIMITIVE, ASN1_OBJECT, ASN1_OCTET_STRING,
    ASN1_TFLG_EXPLICIT, ASN1_TFLG_OPTIONAL, ASN1_TFLG_SEQUENCE_OF, ASN1_TFLG_SET_OF, BIO,
    ERR_LIB_ASN1, ERR_LIB_PKCS12, NID_certBag, NID_crlBag, NID_keyBag, NID_pkcs8ShroudedKeyBag,
    NID_safeContentsBag, NID_sdsiCertificate, NID_secretBag, NID_x509Certificate, NID_x509Crl,
    PKCS7, PKCS12, X509_SIG,
};

use crate::asn1::tpl::free::ASN1_item_free;
use crate::asn1::tpl::io::{
    ASN1_item_d2i_bio_ex, ASN1_item_d2i_fp_ex, ASN1_item_i2d_bio, ASN1_item_i2d_fp,
};
use crate::asn1::tpl::items::{
    ASN1_ANY_it, ASN1_IA5STRING_it, ASN1_INTEGER_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_it, d2i,
    i2d, new_free,
};
use crate::asn1::tpl::statics::{
    Adb, AdbEntries, Templates, adb_entry, adb_object, adb_oid, sequence,
};
use crate::asn1::tpl::{Template, item, item_fns, template, template_at};
use crate::ffi::ffi_export;
use crate::mem;
use crate::pkcs7::PKCS7_it;
use crate::x509::attrib::X509_ATTRIBUTE_it;
use crate::x509::p8::PKCS8_PRIV_KEY_INFO_it;
use crate::x509::sig::X509_SIG_it;

/// A stack, as `STACK_OF(...)` is to C.
pub(crate) type Stack = rustyssl_abi::OPENSSL_STACK;

#[repr(C)]
pub(crate) struct MacData {
    pub(crate) dinfo: *mut X509_SIG,
    pub(crate) salt: *mut ASN1_OCTET_STRING,
    /// 1 when absent.
    pub(crate) iter: *mut ASN1_INTEGER,
}

#[repr(C)]
pub(crate) struct Pfx {
    pub(crate) version: *mut ASN1_INTEGER,
    pub(crate) mac: *mut MacData,
    pub(crate) authsafes: *mut PKCS7,
}

/// A SafeBag: its type, its value (a bag of `Bags`, a PKCS#8 key, a shrouded key, nested bags,
/// or anything else), and its attributes.
#[repr(C)]
pub(crate) struct SafeBag {
    pub(crate) type_: *mut ASN1_OBJECT,
    pub(crate) value: *mut c_void,
    pub(crate) attrib: *mut Stack,
}

/// A certificate, CRL, or secret bag: its type and value (an OCTET STRING, an IA5String, or
/// anything else).
#[repr(C)]
pub(crate) struct Bags {
    pub(crate) type_: *mut ASN1_OBJECT,
    pub(crate) value: *mut c_void,
}

const SIMPLE: c_int = 0;
const OPT: c_int = ASN1_TFLG_OPTIONAL;
const EXP: c_int = ASN1_TFLG_EXPLICIT;
const SET_OF_OPT: c_int = ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL;

macro_rules! tt {
    ($t:ty; $($flags:expr, $tag:expr, $field:ident, $name:literal, $it:expr;)*) => {
        Templates([$(template_at($flags, $tag, offset_of!($t, $field), $name, $it),)*])
    };
}

static PFX_TT: Templates<3> = tt![Pfx;
    SIMPLE, 0, version, c"version", ASN1_INTEGER_it;
    SIMPLE, 0, authsafes, c"authsafes", PKCS7_it;
    OPT, 0, mac, c"mac", PKCS12_MAC_DATA_it;
];

static MAC_TT: Templates<3> = tt![MacData;
    SIMPLE, 0, dinfo, c"dinfo", X509_SIG_it;
    SIMPLE, 0, salt, c"salt", ASN1_OCTET_STRING_it;
    OPT, 0, iter, c"iter", ASN1_INTEGER_it;
];

const BAG_V: usize = offset_of!(Bags, value);

static BAG_DEFAULT: Template = Template(template_at(EXP, 0, BAG_V, c"value.other", ASN1_ANY_it));

static BAG_ADB_TBL: AdbEntries<3> = AdbEntries([
    adb_entry(
        NID_x509Certificate,
        template_at(EXP, 0, BAG_V, c"value.x509cert", ASN1_OCTET_STRING_it),
    ),
    adb_entry(
        NID_x509Crl,
        template_at(EXP, 0, BAG_V, c"value.x509crl", ASN1_OCTET_STRING_it),
    ),
    adb_entry(
        NID_sdsiCertificate,
        template_at(EXP, 0, BAG_V, c"value.sdsicert", ASN1_IA5STRING_it),
    ),
]);

static BAG_ADB: Adb = adb_oid(offset_of!(Bags, type_), &BAG_ADB_TBL, &BAG_DEFAULT);

/// The bags' ANY DEFINED BY table, as an ADB template's item function returns it.
unsafe extern "C" fn bag_adb() -> *const ASN1_ITEM {
    (&raw const BAG_ADB.0).cast()
}

static BAG_TT: Templates<2> = Templates([
    template_at(SIMPLE, 0, offset_of!(Bags, type_), c"type", ASN1_OBJECT_it),
    adb_object(c"PKCS12_BAGS", bag_adb),
]);

const SB_V: usize = offset_of!(SafeBag, value);

static SB_DEFAULT: Template = Template(template_at(EXP, 0, SB_V, c"value.other", ASN1_ANY_it));

static SB_ADB_TBL: AdbEntries<6> = AdbEntries([
    adb_entry(
        NID_keyBag,
        template_at(EXP, 0, SB_V, c"value.keybag", PKCS8_PRIV_KEY_INFO_it),
    ),
    adb_entry(
        NID_pkcs8ShroudedKeyBag,
        template_at(EXP, 0, SB_V, c"value.shkeybag", X509_SIG_it),
    ),
    adb_entry(
        NID_safeContentsBag,
        template_at(
            EXP | ASN1_TFLG_SEQUENCE_OF,
            0,
            SB_V,
            c"value.safes",
            PKCS12_SAFEBAG_it,
        ),
    ),
    adb_entry(
        NID_certBag,
        template_at(EXP, 0, SB_V, c"value.bag", PKCS12_BAGS_it),
    ),
    adb_entry(
        NID_crlBag,
        template_at(EXP, 0, SB_V, c"value.bag", PKCS12_BAGS_it),
    ),
    adb_entry(
        NID_secretBag,
        template_at(EXP, 0, SB_V, c"value.bag", PKCS12_BAGS_it),
    ),
]);

static SB_ADB: Adb = adb_oid(offset_of!(SafeBag, type_), &SB_ADB_TBL, &SB_DEFAULT);

/// The safe bag's ANY DEFINED BY table, as an ADB template's item function returns it.
unsafe extern "C" fn sb_adb() -> *const ASN1_ITEM {
    (&raw const SB_ADB.0).cast()
}

static SB_TT: Templates<3> = Templates([
    template_at(
        SIMPLE,
        0,
        offset_of!(SafeBag, type_),
        c"type",
        ASN1_OBJECT_it,
    ),
    adb_object(c"PKCS12_SAFEBAG", sb_adb),
    template_at(
        SET_OF_OPT,
        0,
        offset_of!(SafeBag, attrib),
        c"attrib",
        X509_ATTRIBUTE_it,
    ),
]);

static SAFEBAGS: Template = template(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    c"PKCS12_SAFEBAGS",
    PKCS12_SAFEBAG_it,
);
static AUTHSAFES: Template = template(ASN1_TFLG_SEQUENCE_OF, 0, c"PKCS12_AUTHSAFES", PKCS7_it);

item_fns! {
    /// PFX: SEQUENCE { version, authSafe ContentInfo, macData OPTIONAL }.
    pub unsafe extern "C" fn PKCS12_it = sequence::<Pfx, 3>(&PFX_TT, None, c"PKCS12");
    /// MacData: SEQUENCE { mac DigestInfo, macSalt, iterations DEFAULT 1 }.
    pub unsafe extern "C" fn PKCS12_MAC_DATA_it = sequence::<MacData, 3>(&MAC_TT, None, c"PKCS12_MAC_DATA");
    /// CertBag, CRLBag, and SecretBag: SEQUENCE { type, value [0] EXPLICIT ANY DEFINED BY type }.
    pub unsafe extern "C" fn PKCS12_BAGS_it = sequence::<Bags, 2>(&BAG_TT, None, c"PKCS12_BAGS");
    /// SafeBag: SEQUENCE { bagId, bagValue [0] EXPLICIT ANY DEFINED BY bagId, bagAttributes
    /// SET OF Attribute OPTIONAL }.
    pub unsafe extern "C" fn PKCS12_SAFEBAG_it = sequence::<SafeBag, 3>(&SB_TT, None, c"PKCS12_SAFEBAG");
    /// SafeContents: SEQUENCE OF SafeBag.
    pub unsafe extern "C" fn PKCS12_SAFEBAGS_it = item(ASN1_ITYPE_PRIMITIVE, -1, (&raw const SAFEBAGS.0).cast(), 0, ptr::null(), 0, c"PKCS12_SAFEBAGS");
    /// AuthenticatedSafe: SEQUENCE OF ContentInfo.
    pub unsafe extern "C" fn PKCS12_AUTHSAFES_it = item(ASN1_ITYPE_PRIMITIVE, -1, (&raw const AUTHSAFES.0).cast(), 0, ptr::null(), 0, c"PKCS12_AUTHSAFES");
}

i2d! {
    /// Encodes a PFX.
    pub unsafe extern "C" fn i2d_PKCS12(PKCS12) = PKCS12_it;
    /// Encodes a MacData.
    pub unsafe extern "C" fn i2d_PKCS12_MAC_DATA(rustyssl_abi::PKCS12_MAC_DATA) = PKCS12_MAC_DATA_it;
    /// Encodes a bag.
    pub unsafe extern "C" fn i2d_PKCS12_BAGS(rustyssl_abi::PKCS12_BAGS) = PKCS12_BAGS_it;
    /// Encodes a SafeBag.
    pub unsafe extern "C" fn i2d_PKCS12_SAFEBAG(rustyssl_abi::PKCS12_SAFEBAG) = PKCS12_SAFEBAG_it;
}

d2i! {
    /// Decodes a PFX.
    pub unsafe extern "C" fn d2i_PKCS12(PKCS12) = PKCS12_it;
    /// Decodes a MacData.
    pub unsafe extern "C" fn d2i_PKCS12_MAC_DATA(rustyssl_abi::PKCS12_MAC_DATA) = PKCS12_MAC_DATA_it;
    /// Decodes a bag.
    pub unsafe extern "C" fn d2i_PKCS12_BAGS(rustyssl_abi::PKCS12_BAGS) = PKCS12_BAGS_it;
    /// Decodes a SafeBag.
    pub unsafe extern "C" fn d2i_PKCS12_SAFEBAG(rustyssl_abi::PKCS12_SAFEBAG) = PKCS12_SAFEBAG_it;
}

new_free! {
    pub unsafe extern "C" fn PKCS12_MAC_DATA_new, pub unsafe extern "C" fn PKCS12_MAC_DATA_free(rustyssl_abi::PKCS12_MAC_DATA) = PKCS12_MAC_DATA_it;
    pub unsafe extern "C" fn PKCS12_BAGS_new, pub unsafe extern "C" fn PKCS12_BAGS_free(rustyssl_abi::PKCS12_BAGS) = PKCS12_BAGS_it;
    pub unsafe extern "C" fn PKCS12_SAFEBAG_new, pub unsafe extern "C" fn PKCS12_SAFEBAG_free(rustyssl_abi::PKCS12_SAFEBAG) = PKCS12_SAFEBAG_it;
}

ffi_export! {
    /// A new, empty PFX, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn PKCS12_new() -> *mut PKCS12
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: no preconditions.
        let it = unsafe { PKCS12_it() };
        // SAFETY: the item.
        unsafe { crate::asn1::tpl::new::ASN1_item_new(it) }.cast()
    }
}

ffi_export! {
    /// Frees a PFX and its authenticated safe's properties (nothing for NULL).
    ///
    /// # Safety
    /// `p12` is NULL or a PFX not used after.
    pub unsafe extern "C" fn PKCS12_free(p12: *mut PKCS12)
    where failure = (), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee; its authenticated safe, NULL or live.
        if let Some(p7) = unsafe { p12.cast::<Pfx>().as_ref() }.and_then(|p| unsafe { p.authsafes.as_mut() }) {
            // SAFETY: its own copy, or NULL.
            unsafe { mem::release(p7.ctx.propq.cast()) };
            p7.ctx.propq = ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let it = unsafe { PKCS12_it() };
        // SAFETY: the object, of the item.
        unsafe { ASN1_item_free(p12.cast(), it) };
    }
}

/// The octets of a string, empty for NULL.
///
/// # Safety
/// `os` is NULL or a live string, unchanged while the slice lives.
pub(crate) unsafe fn octets<'a>(os: *const rustyssl_abi::ASN1_STRING) -> &'a [u8] {
    // SAFETY: the caller's guarantee.
    unsafe { os.as_ref() }.map_or(&[], |s| unsafe {
        crate::asn1::text::octets(s.data, s.length)
    })
}

/// The PFX behind a pointer.
///
/// # Safety
/// `p12` is NULL or a live PFX.
pub(crate) unsafe fn pfx_of<'a>(p12: *const PKCS12) -> Option<&'a mut Pfx> {
    // SAFETY: the caller's guarantee.
    unsafe { p12.cast::<Pfx>().cast_mut().as_mut() }
}

/// The safe bag behind a pointer.
///
/// # Safety
/// `bag` is NULL or a live safe bag.
pub(crate) unsafe fn bag_of<'a>(
    bag: *const rustyssl_abi::PKCS12_SAFEBAG,
) -> Option<&'a mut SafeBag> {
    // SAFETY: the caller's guarantee.
    unsafe { bag.cast::<SafeBag>().cast_mut().as_mut() }
}

/// The library context and properties of a PFX's authenticated safe, if any
/// (`ossl_pkcs12_get0_pkcs7ctx`).
///
/// # Safety
/// `p12` is NULL or a live PFX.
pub(crate) unsafe fn p7ctx(
    p12: *const PKCS12,
) -> (*mut rustyssl_abi::OSSL_LIB_CTX, *const core::ffi::c_char) {
    // SAFETY: the caller's guarantee; its authenticated safe, NULL or live.
    unsafe { pfx_of(p12) }
        .and_then(|p| unsafe { p.authsafes.as_ref() })
        .map_or((ptr::null_mut(), ptr::null()), |p7| {
            (p7.ctx.libctx, p7.ctx.propq.cast_const())
        })
}

ffi_export! {
    /// Writes a PFX's DER to a BIO: 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `p12` a live PFX.
    pub unsafe extern "C" fn i2d_PKCS12_bio(bp: *mut BIO, p12: *const PKCS12) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        // SAFETY: no preconditions.
        let it = unsafe { PKCS12_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_bio(it, bp, p12.cast()) }
    }
}

ffi_export! {
    /// Writes a PFX's DER to a file: 1, or 0.
    ///
    /// # Safety
    /// `fp` is a live file; `p12` a live PFX.
    pub unsafe extern "C" fn i2d_PKCS12_fp(fp: *mut FILE, p12: *const PKCS12) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        // SAFETY: no preconditions.
        let it = unsafe { PKCS12_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_fp(it, fp, p12.cast()) }
    }
}

ffi_export! {
    /// Reads a PFX's DER from a BIO (in `*p12`'s library context, if any), or NULL.
    ///
    /// # Safety
    /// `bp` is a live BIO; `p12` NULL or holding NULL or a live PFX.
    pub unsafe extern "C" fn d2i_PKCS12_bio(bp: *mut BIO, p12: *mut *mut PKCS12) -> *mut PKCS12
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let (libctx, propq) = unsafe { p12.as_ref() }.map_or((ptr::null_mut(), ptr::null()), |&p| unsafe { p7ctx(p) });
        // SAFETY: no preconditions.
        let it = unsafe { PKCS12_it() };
        // SAFETY: as above.
        unsafe { ASN1_item_d2i_bio_ex(it, bp, p12.cast(), libctx, propq) }.cast()
    }
}

ffi_export! {
    /// Reads a PFX's DER from a file (in `*p12`'s library context, if any), or NULL.
    ///
    /// # Safety
    /// `fp` is a live file; `p12` NULL or holding NULL or a live PFX.
    pub unsafe extern "C" fn d2i_PKCS12_fp(fp: *mut FILE, p12: *mut *mut PKCS12) -> *mut PKCS12
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let (libctx, propq) = unsafe { p12.as_ref() }.map_or((ptr::null_mut(), ptr::null()), |&p| unsafe { p7ctx(p) });
        // SAFETY: no preconditions.
        let it = unsafe { PKCS12_it() };
        // SAFETY: as above.
        unsafe { ASN1_item_d2i_fp_ex(it, fp, p12.cast(), libctx, propq) }.cast()
    }
}
