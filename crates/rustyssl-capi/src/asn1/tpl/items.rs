//! The universal types' items (`tasn_typ.c`, `a_time.c`): primitives by `V_ASN1_*` type, the
//! MSTRING items that take any of a mask of string types, the three BOOLEAN items (whose size
//! is the default left out of an encoding: -1 for none), SEQUENCE OF / SET OF ANY, and
//! `X509_ALGOR` (`x_algor.c`), the AlgorithmIdentifier the EVP layer decodes. With them, their
//! `new`, `free`, and `i2d_` functions, each through its item.

use core::ffi::c_int;
use core::ptr;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_BMPSTRING, ASN1_ENUMERATED, ASN1_GENERALIZEDTIME, ASN1_GENERALSTRING,
    ASN1_IA5STRING, ASN1_INTEGER, ASN1_ITEM, ASN1_ITYPE_MSTRING, ASN1_ITYPE_PRIMITIVE,
    ASN1_ITYPE_SEQUENCE, ASN1_NULL, ASN1_OCTET_STRING, ASN1_PRINTABLESTRING, ASN1_SEQUENCE_ANY,
    ASN1_STRING, ASN1_T61STRING, ASN1_TEMPLATE, ASN1_TFLG_NDEF, ASN1_TFLG_OPTIONAL,
    ASN1_TFLG_SEQUENCE_OF, ASN1_TFLG_SET_OF, ASN1_TIME, ASN1_TYPE, ASN1_UNIVERSALSTRING,
    ASN1_UTCTIME, ASN1_UTF8STRING, ASN1_VISIBLESTRING, B_ASN1_DIRECTORYSTRING, B_ASN1_DISPLAYTEXT,
    B_ASN1_PRINTABLE, B_ASN1_TIME, ERR_LIB_ASN1, V_ASN1_ANY, V_ASN1_BIT_STRING, V_ASN1_BMPSTRING,
    V_ASN1_BOOLEAN, V_ASN1_ENUMERATED, V_ASN1_GENERALIZEDTIME, V_ASN1_GENERALSTRING,
    V_ASN1_IA5STRING, V_ASN1_INTEGER, V_ASN1_NULL, V_ASN1_OBJECT, V_ASN1_OCTET_STRING,
    V_ASN1_PRINTABLESTRING, V_ASN1_SEQUENCE, V_ASN1_T61STRING, V_ASN1_UNIVERSALSTRING,
    V_ASN1_UTCTIME, V_ASN1_UTF8STRING, V_ASN1_VISIBLESTRING, X509_ALGOR,
};

use super::{Item, Template, item, item_fns, size_of_long, template, template_at};

/// A primitive item of type `utype`, with `size` (`IMPLEMENT_ASN1_TYPE_ex`).
const fn primitive(utype: c_int, size: core::ffi::c_long, sname: &'static core::ffi::CStr) -> Item {
    item(
        ASN1_ITYPE_PRIMITIVE,
        utype,
        ptr::null(),
        0,
        ptr::null(),
        size,
        sname,
    )
}

/// A primitive item (`IMPLEMENT_ASN1_TYPE`), whose size is 0.
const fn universal(utype: c_int, sname: &'static core::ffi::CStr) -> Item {
    primitive(utype, 0, sname)
}

/// An MSTRING item taking the types in `mask` (`IMPLEMENT_ASN1_MSTRING`).
const fn mstring(mask: c_int, sname: &'static core::ffi::CStr) -> Item {
    item(
        ASN1_ITYPE_MSTRING,
        mask,
        ptr::null(),
        0,
        ptr::null(),
        size_of_long::<ASN1_STRING>(),
        sname,
    )
}

item_fns! {
    /// The OCTET STRING item.
    pub unsafe extern "C" fn ASN1_OCTET_STRING_it = universal(V_ASN1_OCTET_STRING, c"ASN1_OCTET_STRING");
    /// The INTEGER item.
    pub unsafe extern "C" fn ASN1_INTEGER_it = universal(V_ASN1_INTEGER, c"ASN1_INTEGER");
    /// The ENUMERATED item.
    pub unsafe extern "C" fn ASN1_ENUMERATED_it = universal(V_ASN1_ENUMERATED, c"ASN1_ENUMERATED");
    /// The BIT STRING item.
    pub unsafe extern "C" fn ASN1_BIT_STRING_it = universal(V_ASN1_BIT_STRING, c"ASN1_BIT_STRING");
    /// The UTF8String item.
    pub unsafe extern "C" fn ASN1_UTF8STRING_it = universal(V_ASN1_UTF8STRING, c"ASN1_UTF8STRING");
    /// The PrintableString item.
    pub unsafe extern "C" fn ASN1_PRINTABLESTRING_it = universal(V_ASN1_PRINTABLESTRING, c"ASN1_PRINTABLESTRING");
    /// The T61String item.
    pub unsafe extern "C" fn ASN1_T61STRING_it = universal(V_ASN1_T61STRING, c"ASN1_T61STRING");
    /// The IA5String item.
    pub unsafe extern "C" fn ASN1_IA5STRING_it = universal(V_ASN1_IA5STRING, c"ASN1_IA5STRING");
    /// The GeneralString item.
    pub unsafe extern "C" fn ASN1_GENERALSTRING_it = universal(V_ASN1_GENERALSTRING, c"ASN1_GENERALSTRING");
    /// The UTCTime item.
    pub unsafe extern "C" fn ASN1_UTCTIME_it = universal(V_ASN1_UTCTIME, c"ASN1_UTCTIME");
    /// The GeneralizedTime item.
    pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_it = universal(V_ASN1_GENERALIZEDTIME, c"ASN1_GENERALIZEDTIME");
    /// The VisibleString item.
    pub unsafe extern "C" fn ASN1_VISIBLESTRING_it = universal(V_ASN1_VISIBLESTRING, c"ASN1_VISIBLESTRING");
    /// The UniversalString item.
    pub unsafe extern "C" fn ASN1_UNIVERSALSTRING_it = universal(V_ASN1_UNIVERSALSTRING, c"ASN1_UNIVERSALSTRING");
    /// The BMPString item.
    pub unsafe extern "C" fn ASN1_BMPSTRING_it = universal(V_ASN1_BMPSTRING, c"ASN1_BMPSTRING");
    /// The NULL item, whose value is the pointer 1.
    pub unsafe extern "C" fn ASN1_NULL_it = universal(V_ASN1_NULL, c"ASN1_NULL");
    /// The OBJECT IDENTIFIER item.
    pub unsafe extern "C" fn ASN1_OBJECT_it = universal(V_ASN1_OBJECT, c"ASN1_OBJECT");
    /// The ANY item, whose value is an `ASN1_TYPE`.
    pub unsafe extern "C" fn ASN1_ANY_it = universal(V_ASN1_ANY, c"ASN1_ANY");
    /// A SEQUENCE kept as its whole encoding in an `ASN1_STRING`.
    pub unsafe extern "C" fn ASN1_SEQUENCE_it = universal(V_ASN1_SEQUENCE, c"ASN1_SEQUENCE");
    /// The BOOLEAN item, always encoded.
    pub unsafe extern "C" fn ASN1_BOOLEAN_it = primitive(V_ASN1_BOOLEAN, -1, c"ASN1_BOOLEAN");
    /// The BOOLEAN item defaulting to TRUE (left out when true).
    pub unsafe extern "C" fn ASN1_TBOOLEAN_it = primitive(V_ASN1_BOOLEAN, 1, c"ASN1_TBOOLEAN");
    /// The BOOLEAN item defaulting to FALSE (left out when false).
    pub unsafe extern "C" fn ASN1_FBOOLEAN_it = primitive(V_ASN1_BOOLEAN, 0, c"ASN1_FBOOLEAN");
    /// An OCTET STRING that may be streamed with the indefinite length.
    pub unsafe extern "C" fn ASN1_OCTET_STRING_NDEF_it = primitive(V_ASN1_OCTET_STRING, ASN1_TFLG_NDEF as core::ffi::c_long, c"ASN1_OCTET_STRING_NDEF");
    /// Any of the printable string types (`B_ASN1_PRINTABLE`).
    pub unsafe extern "C" fn ASN1_PRINTABLE_it = mstring(B_ASN1_PRINTABLE, c"ASN1_PRINTABLE");
    /// DisplayText's string types.
    pub unsafe extern "C" fn DISPLAYTEXT_it = mstring(B_ASN1_DISPLAYTEXT, c"DISPLAYTEXT");
    /// DirectoryString's string types.
    pub unsafe extern "C" fn DIRECTORYSTRING_it = mstring(B_ASN1_DIRECTORYSTRING, c"DIRECTORYSTRING");
    /// Time: a UTCTime or GeneralizedTime.
    pub unsafe extern "C" fn ASN1_TIME_it = mstring(B_ASN1_TIME, c"ASN1_TIME");
}

/// The template of `ASN1_SEQUENCE_ANY`.
static SEQUENCE_ANY: Template =
    template(ASN1_TFLG_SEQUENCE_OF, 0, c"ASN1_SEQUENCE_ANY", ASN1_ANY_it);

/// The template of `ASN1_SET_ANY`.
static SET_ANY: Template = template(ASN1_TFLG_SET_OF, 0, c"ASN1_SET_ANY", ASN1_ANY_it);

item_fns! {
    /// A SEQUENCE OF ANY, a stack of `ASN1_TYPE`s.
    pub unsafe extern "C" fn ASN1_SEQUENCE_ANY_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const SEQUENCE_ANY.0, 0, ptr::null(), 0, c"ASN1_SEQUENCE_ANY");
    /// A SET OF ANY, a stack of `ASN1_TYPE`s.
    pub unsafe extern "C" fn ASN1_SET_ANY_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const SET_ANY.0, 0, ptr::null(), 0, c"ASN1_SET_ANY");
}

/// The templates of `X509_ALGOR`: its OID, then its parameters, optional.
struct AlgorTemplates([ASN1_TEMPLATE; 2]);
// SAFETY: immutable tables of pointers to static data.
unsafe impl Sync for AlgorTemplates {}

static ALGOR_TT: AlgorTemplates = AlgorTemplates([
    template_at(
        0,
        0,
        core::mem::offset_of!(X509_ALGOR, algorithm),
        c"algorithm",
        ASN1_OBJECT_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        core::mem::offset_of!(X509_ALGOR, parameter),
        c"parameter",
        ASN1_ANY_it,
    ),
]);

item_fns! {
    /// AlgorithmIdentifier: SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }.
    pub unsafe extern "C" fn X509_ALGOR_it = item(ASN1_ITYPE_SEQUENCE, V_ASN1_SEQUENCE, &raw const ALGOR_TT.0 as *const ASN1_TEMPLATE, 2, ptr::null(), size_of_long::<X509_ALGOR>(), c"X509_ALGOR");
}

/// Defines `i2d_` functions, each encoding through its item.
macro_rules! i2d {
    ($(
        $(#[$attr:meta])*
        pub unsafe extern "C" fn $name:ident($ty:ty) = $it:ident;
    )*) => {$(
        $crate::ffi::ffi_export! {
            $(#[$attr])*
            ///
            /// # Safety
            /// As for `ASN1_item_i2d`, with `a` a value of the type.
            pub unsafe extern "C" fn $name(a: *const $ty, out: *mut *mut ::core::ffi::c_uchar) -> ::core::ffi::c_int
            where failure = -1, library = ::rustyssl_abi::ERR_LIB_ASN1
            {
                // SAFETY: the caller's guarantee; the item is the type's.
                unsafe { $crate::asn1::tpl::encode::ASN1_item_i2d(a.cast(), out, $it()) }
            }
        }
    )*};
}

pub(crate) use i2d;

i2d! {
    /// Encodes an OCTET STRING (`ASN1_item_i2d`).
    pub unsafe extern "C" fn i2d_ASN1_OCTET_STRING(ASN1_OCTET_STRING) = ASN1_OCTET_STRING_it;
    /// Encodes an INTEGER.
    pub unsafe extern "C" fn i2d_ASN1_INTEGER(ASN1_INTEGER) = ASN1_INTEGER_it;
    /// Encodes an ENUMERATED.
    pub unsafe extern "C" fn i2d_ASN1_ENUMERATED(ASN1_ENUMERATED) = ASN1_ENUMERATED_it;
    /// Encodes a BIT STRING.
    pub unsafe extern "C" fn i2d_ASN1_BIT_STRING(ASN1_BIT_STRING) = ASN1_BIT_STRING_it;
    /// Encodes a UTF8String.
    pub unsafe extern "C" fn i2d_ASN1_UTF8STRING(ASN1_UTF8STRING) = ASN1_UTF8STRING_it;
    /// Encodes a PrintableString.
    pub unsafe extern "C" fn i2d_ASN1_PRINTABLESTRING(ASN1_PRINTABLESTRING) = ASN1_PRINTABLESTRING_it;
    /// Encodes a T61String.
    pub unsafe extern "C" fn i2d_ASN1_T61STRING(ASN1_T61STRING) = ASN1_T61STRING_it;
    /// Encodes an IA5String.
    pub unsafe extern "C" fn i2d_ASN1_IA5STRING(ASN1_IA5STRING) = ASN1_IA5STRING_it;
    /// Encodes a GeneralString.
    pub unsafe extern "C" fn i2d_ASN1_GENERALSTRING(ASN1_GENERALSTRING) = ASN1_GENERALSTRING_it;
    /// Encodes a UTCTime.
    pub unsafe extern "C" fn i2d_ASN1_UTCTIME(ASN1_UTCTIME) = ASN1_UTCTIME_it;
    /// Encodes a GeneralizedTime.
    pub unsafe extern "C" fn i2d_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME) = ASN1_GENERALIZEDTIME_it;
    /// Encodes a VisibleString.
    pub unsafe extern "C" fn i2d_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING) = ASN1_VISIBLESTRING_it;
    /// Encodes a UniversalString.
    pub unsafe extern "C" fn i2d_ASN1_UNIVERSALSTRING(ASN1_UNIVERSALSTRING) = ASN1_UNIVERSALSTRING_it;
    /// Encodes a BMPString.
    pub unsafe extern "C" fn i2d_ASN1_BMPSTRING(ASN1_BMPSTRING) = ASN1_BMPSTRING_it;
    /// Encodes a NULL.
    pub unsafe extern "C" fn i2d_ASN1_NULL(ASN1_NULL) = ASN1_NULL_it;
    /// Encodes an `ASN1_TYPE` as the value it holds.
    pub unsafe extern "C" fn i2d_ASN1_TYPE(ASN1_TYPE) = ASN1_ANY_it;
    /// Encodes a Time as the UTCTime or GeneralizedTime it holds.
    pub unsafe extern "C" fn i2d_ASN1_TIME(ASN1_TIME) = ASN1_TIME_it;
    /// Encodes an `ASN1_PRINTABLE` string as its type.
    pub unsafe extern "C" fn i2d_ASN1_PRINTABLE(ASN1_STRING) = ASN1_PRINTABLE_it;
    /// Encodes a DirectoryString as its type.
    pub unsafe extern "C" fn i2d_DIRECTORYSTRING(ASN1_STRING) = DIRECTORYSTRING_it;
    /// Encodes a DisplayText as its type.
    pub unsafe extern "C" fn i2d_DISPLAYTEXT(ASN1_STRING) = DISPLAYTEXT_it;
    /// Encodes a stack of `ASN1_TYPE`s as a SEQUENCE OF ANY.
    pub unsafe extern "C" fn i2d_ASN1_SEQUENCE_ANY(ASN1_SEQUENCE_ANY) = ASN1_SEQUENCE_ANY_it;
    /// Encodes a stack of `ASN1_TYPE`s as a SET OF ANY, in DER order.
    pub unsafe extern "C" fn i2d_ASN1_SET_ANY(ASN1_SEQUENCE_ANY) = ASN1_SET_ANY_it;
    /// Encodes an AlgorithmIdentifier.
    pub unsafe extern "C" fn i2d_X509_ALGOR(X509_ALGOR) = X509_ALGOR_it;
}

/// Defines `d2i_` functions, each decoding through its item.
macro_rules! d2i {
    ($(
        $(#[$attr:meta])*
        pub unsafe extern "C" fn $name:ident($ty:ty) = $it:ident;
    )*) => {$(
        $crate::ffi::ffi_export! {
            $(#[$attr])*
            ///
            /// # Safety
            /// As for `ASN1_item_d2i`, with `a` NULL or a slot for a value of the type.
            pub unsafe extern "C" fn $name(a: *mut *mut $ty, in_: *mut *const ::core::ffi::c_uchar, len: ::core::ffi::c_long) -> *mut $ty
            where failure = ::core::ptr::null_mut(), library = ::rustyssl_abi::ERR_LIB_ASN1
            {
                // SAFETY: the caller's guarantee; the item is the type's.
                unsafe { $crate::asn1::tpl::decode::ASN1_item_d2i(a.cast(), in_, len, $it()) }.cast()
            }
        }
    )*};
}

pub(crate) use d2i;

d2i! {
    /// Decodes an OCTET STRING (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_OCTET_STRING(ASN1_OCTET_STRING) = ASN1_OCTET_STRING_it;
    /// Decodes an INTEGER (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_INTEGER(ASN1_INTEGER) = ASN1_INTEGER_it;
    /// Decodes an ENUMERATED (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_ENUMERATED(ASN1_ENUMERATED) = ASN1_ENUMERATED_it;
    /// Decodes a BIT STRING (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_BIT_STRING(ASN1_BIT_STRING) = ASN1_BIT_STRING_it;
    /// Decodes a UTF8String (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_UTF8STRING(ASN1_UTF8STRING) = ASN1_UTF8STRING_it;
    /// Decodes a PrintableString (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_PRINTABLESTRING(ASN1_PRINTABLESTRING) = ASN1_PRINTABLESTRING_it;
    /// Decodes a T61String (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_T61STRING(ASN1_T61STRING) = ASN1_T61STRING_it;
    /// Decodes an IA5String (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_IA5STRING(ASN1_IA5STRING) = ASN1_IA5STRING_it;
    /// Decodes a GeneralString (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_GENERALSTRING(ASN1_GENERALSTRING) = ASN1_GENERALSTRING_it;
    /// Decodes a UTCTime (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_UTCTIME(ASN1_UTCTIME) = ASN1_UTCTIME_it;
    /// Decodes a GeneralizedTime (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME) = ASN1_GENERALIZEDTIME_it;
    /// Decodes a VisibleString (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING) = ASN1_VISIBLESTRING_it;
    /// Decodes a UniversalString (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_UNIVERSALSTRING(ASN1_UNIVERSALSTRING) = ASN1_UNIVERSALSTRING_it;
    /// Decodes a BMPString (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_BMPSTRING(ASN1_BMPSTRING) = ASN1_BMPSTRING_it;
    /// Decodes a NULL (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_NULL(ASN1_NULL) = ASN1_NULL_it;
    /// Decodes any value, as an `ASN1_TYPE` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_TYPE(ASN1_TYPE) = ASN1_ANY_it;
    /// Decodes a UTCTime or GeneralizedTime, as a Time (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_TIME(ASN1_TIME) = ASN1_TIME_it;
    /// Decodes one of the printable string types (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_PRINTABLE(ASN1_STRING) = ASN1_PRINTABLE_it;
    /// Decodes a DirectoryString (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_DIRECTORYSTRING(ASN1_STRING) = DIRECTORYSTRING_it;
    /// Decodes a DisplayText (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_DISPLAYTEXT(ASN1_STRING) = DISPLAYTEXT_it;
    /// Decodes a SEQUENCE OF ANY, as a stack of `ASN1_TYPE`s (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_SEQUENCE_ANY(ASN1_SEQUENCE_ANY) = ASN1_SEQUENCE_ANY_it;
    /// Decodes a SET OF ANY, as a stack of `ASN1_TYPE`s (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ASN1_SET_ANY(ASN1_SEQUENCE_ANY) = ASN1_SET_ANY_it;
    /// Decodes an AlgorithmIdentifier (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_X509_ALGOR(X509_ALGOR) = X509_ALGOR_it;
}

/// Defines `_new` and `_free` functions through an item.
macro_rules! new_free {
    ($(
        pub unsafe extern "C" fn $new:ident, pub unsafe extern "C" fn $free:ident ($ty:ty) = $it:ident;
    )*) => {$(
        $crate::ffi::ffi_export! {
            #[doc = concat!("A new value of `", stringify!($it), "` (`ASN1_item_new`).")]
            ///
            /// # Safety
            /// No preconditions.
            pub unsafe extern "C" fn $new() -> *mut $ty
            where failure = ::core::ptr::null_mut(), library = ::rustyssl_abi::ERR_LIB_ASN1
            {
                // SAFETY: the type's item.
                unsafe { $crate::asn1::tpl::new::ASN1_item_new($it()) }.cast()
            }
        }

        $crate::ffi::ffi_export! {
            #[doc = concat!("Frees a value of `", stringify!($it), "` (`ASN1_item_free`).")]
            ///
            /// # Safety
            /// `a` is NULL or a live value of the type.
            pub unsafe extern "C" fn $free(a: *mut $ty)
            where failure = (), library = ::rustyssl_abi::ERR_LIB_ASN1
            {
                // SAFETY: the caller's guarantee.
                unsafe { $crate::asn1::tpl::free::ASN1_item_free(a.cast(), $it()) }
            }
        }
    )*};
}

pub(crate) use new_free;

new_free! {
    pub unsafe extern "C" fn ASN1_NULL_new, pub unsafe extern "C" fn ASN1_NULL_free(ASN1_NULL) = ASN1_NULL_it;
    pub unsafe extern "C" fn ASN1_TYPE_new, pub unsafe extern "C" fn ASN1_TYPE_free(ASN1_TYPE) = ASN1_ANY_it;
    pub unsafe extern "C" fn ASN1_TIME_new, pub unsafe extern "C" fn ASN1_TIME_free(ASN1_TIME) = ASN1_TIME_it;
    pub unsafe extern "C" fn ASN1_PRINTABLE_new, pub unsafe extern "C" fn ASN1_PRINTABLE_free(ASN1_STRING) = ASN1_PRINTABLE_it;
    pub unsafe extern "C" fn DIRECTORYSTRING_new, pub unsafe extern "C" fn DIRECTORYSTRING_free(ASN1_STRING) = DIRECTORYSTRING_it;
    pub unsafe extern "C" fn DISPLAYTEXT_new, pub unsafe extern "C" fn DISPLAYTEXT_free(ASN1_STRING) = DISPLAYTEXT_it;
    pub unsafe extern "C" fn X509_ALGOR_new, pub unsafe extern "C" fn X509_ALGOR_free(X509_ALGOR) = X509_ALGOR_it;
}
