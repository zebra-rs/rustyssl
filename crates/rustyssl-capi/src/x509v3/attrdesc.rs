//! Attribute descriptors, attribute mappings, and allowed attribute assignments (ITU-T X.509's,
//! `v3_attrdesc.c`, `v3_attrmap.c`, `v3_aaa.c`): attribute certificate extensions that print
//! (`i2r`) but aren't made from configuration, as OpenSSL's.
//!
//! As OpenSSL's printing, the OIDs of descriptors and privilege policies are cut to 79
//! characters, a descriptor's content mustn't be empty, a hash must have its value, and
//! attribute mappings print nothing, and fail, at no indent.

use core::ffi::{c_int, c_long, c_void};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_ITYPE_PRIMITIVE, ASN1_TFLG_EXPLICIT, ASN1_TFLG_IMPLICIT, ASN1_TFLG_OPTIONAL,
    ASN1_TFLG_SET_OF, BIO, ERR_LIB_ASN1, ERR_LIB_X509V3, NID_allowed_attribute_assignments,
    NID_attribute_descriptor, NID_attribute_mappings, OSSL_AAA_ATTRIBUTE_TYPE,
    OSSL_AAA_ATTRIBUTE_VALUES, OSSL_ALLOWED_ATTRIBUTES_CHOICE, OSSL_ALLOWED_ATTRIBUTES_ITEM,
    OSSL_ALLOWED_ATTRIBUTES_SYNTAX, OSSL_ATAV, OSSL_ATTR_MAP_TYPE, OSSL_ATTR_MAP_VALUE,
    OSSL_ATTRIBUTE_DESCRIPTOR, OSSL_ATTRIBUTE_MAPPING, OSSL_ATTRIBUTE_MAPPINGS,
    OSSL_ATTRIBUTE_TYPE_MAPPING, OSSL_ATTRIBUTE_VALUE_MAPPING, OSSL_HASH, OSSL_INFO_SYNTAX,
    OSSL_INFO_SYNTAX_POINTER, OSSL_INFO_SYNTAX_TYPE_CONTENT, OSSL_INFO_SYNTAX_TYPE_POINTER,
    OSSL_PRIVILEGE_POLICY_ID, X509V3_EXT_METHOD, X509V3_EXT_MULTILINE,
};

use super::crld::OSSL_GENERAL_NAMES_print;
use super::genn::{GENERAL_NAME_it, GENERAL_NAMES_it};
use super::item_at;
use super::registry::{Method, method};
use super::san::GENERAL_NAME_print;
use super::text::{Out, precision_text};
use crate::asn1::tpl::items::{
    ASN1_ANY_it, ASN1_BIT_STRING_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_it, ASN1_UTF8STRING_it,
    DIRECTORYSTRING_it, X509_ALGOR_it, d2i, i2d, new_free,
};
use crate::asn1::tpl::statics::{Templates, choice, sequence};
use crate::asn1::tpl::{Template, item, item_fns, template, template_at};
use crate::ffi::ffi_callback;
use crate::objects::{OBJ_obj2nid, i2a_ASN1_OBJECT};
use crate::stack::OPENSSL_sk_num;
use crate::x509::attrib::{
    X509_ATTRIBUTE_count, X509_ATTRIBUTE_get0_object, X509_ATTRIBUTE_get0_type, X509_ATTRIBUTE_it,
};
use crate::x509::attrval::{bio_print_hex, oid_text80, print_attribute_value};

// The items.

static HASH_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(OSSL_HASH, algorithmIdentifier),
        c"algorithmIdentifier",
        X509_ALGOR_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(OSSL_HASH, hashValue),
        c"hashValue",
        ASN1_BIT_STRING_it,
    ),
]);

item_fns! {
    /// A hash: the algorithm and an optional BIT STRING value.
    pub unsafe extern "C" fn OSSL_HASH_it = sequence::<OSSL_HASH, 2>(&HASH_TT, None, c"OSSL_HASH");
}

new_free! {
    pub unsafe extern "C" fn OSSL_HASH_new, pub unsafe extern "C" fn OSSL_HASH_free(OSSL_HASH) = OSSL_HASH_it;
}

i2d! {
    /// Encodes an `OSSL_HASH`.
    pub unsafe extern "C" fn i2d_OSSL_HASH(OSSL_HASH) = OSSL_HASH_it;
}

d2i! {
    /// Decodes an `OSSL_HASH` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_HASH(OSSL_HASH) = OSSL_HASH_it;
}

static POINTER_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(OSSL_INFO_SYNTAX_POINTER, name),
        c"name",
        GENERAL_NAMES_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(OSSL_INFO_SYNTAX_POINTER, hash),
        c"hash",
        OSSL_HASH_it,
    ),
]);

item_fns! {
    /// An information syntax pointer: names and an optional hash.
    pub unsafe extern "C" fn OSSL_INFO_SYNTAX_POINTER_it = sequence::<OSSL_INFO_SYNTAX_POINTER, 2>(&POINTER_TT, None, c"OSSL_INFO_SYNTAX_POINTER");
}

new_free! {
    pub unsafe extern "C" fn OSSL_INFO_SYNTAX_POINTER_new, pub unsafe extern "C" fn OSSL_INFO_SYNTAX_POINTER_free(OSSL_INFO_SYNTAX_POINTER) = OSSL_INFO_SYNTAX_POINTER_it;
}

i2d! {
    /// Encodes an `OSSL_INFO_SYNTAX_POINTER`.
    pub unsafe extern "C" fn i2d_OSSL_INFO_SYNTAX_POINTER(OSSL_INFO_SYNTAX_POINTER) = OSSL_INFO_SYNTAX_POINTER_it;
}

d2i! {
    /// Decodes an `OSSL_INFO_SYNTAX_POINTER` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_INFO_SYNTAX_POINTER(OSSL_INFO_SYNTAX_POINTER) = OSSL_INFO_SYNTAX_POINTER_it;
}

static INFO_SYNTAX_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(OSSL_INFO_SYNTAX, choice),
        c"choice.content",
        DIRECTORYSTRING_it,
    ),
    template_at(
        0,
        0,
        offset_of!(OSSL_INFO_SYNTAX, choice),
        c"choice.pointer",
        OSSL_INFO_SYNTAX_POINTER_it,
    ),
]);

item_fns! {
    /// An information syntax: content (a DirectoryString) or a pointer.
    pub unsafe extern "C" fn OSSL_INFO_SYNTAX_it = choice::<OSSL_INFO_SYNTAX, 2>(&INFO_SYNTAX_TT, offset_of!(OSSL_INFO_SYNTAX, type_), None, c"OSSL_INFO_SYNTAX");
}

new_free! {
    pub unsafe extern "C" fn OSSL_INFO_SYNTAX_new, pub unsafe extern "C" fn OSSL_INFO_SYNTAX_free(OSSL_INFO_SYNTAX) = OSSL_INFO_SYNTAX_it;
}

i2d! {
    /// Encodes an `OSSL_INFO_SYNTAX`.
    pub unsafe extern "C" fn i2d_OSSL_INFO_SYNTAX(OSSL_INFO_SYNTAX) = OSSL_INFO_SYNTAX_it;
}

d2i! {
    /// Decodes an `OSSL_INFO_SYNTAX` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_INFO_SYNTAX(OSSL_INFO_SYNTAX) = OSSL_INFO_SYNTAX_it;
}

static PPID_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(OSSL_PRIVILEGE_POLICY_ID, privilegePolicy),
        c"privilegePolicy",
        ASN1_OBJECT_it,
    ),
    template_at(
        0,
        0,
        offset_of!(OSSL_PRIVILEGE_POLICY_ID, privPolSyntax),
        c"privPolSyntax",
        OSSL_INFO_SYNTAX_it,
    ),
]);

item_fns! {
    /// A privilege policy identifier: the policy and its syntax.
    pub unsafe extern "C" fn OSSL_PRIVILEGE_POLICY_ID_it = sequence::<OSSL_PRIVILEGE_POLICY_ID, 2>(&PPID_TT, None, c"OSSL_PRIVILEGE_POLICY_ID");
}

new_free! {
    pub unsafe extern "C" fn OSSL_PRIVILEGE_POLICY_ID_new, pub unsafe extern "C" fn OSSL_PRIVILEGE_POLICY_ID_free(OSSL_PRIVILEGE_POLICY_ID) = OSSL_PRIVILEGE_POLICY_ID_it;
}

i2d! {
    /// Encodes an `OSSL_PRIVILEGE_POLICY_ID`.
    pub unsafe extern "C" fn i2d_OSSL_PRIVILEGE_POLICY_ID(OSSL_PRIVILEGE_POLICY_ID) = OSSL_PRIVILEGE_POLICY_ID_it;
}

d2i! {
    /// Decodes an `OSSL_PRIVILEGE_POLICY_ID` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_PRIVILEGE_POLICY_ID(OSSL_PRIVILEGE_POLICY_ID) = OSSL_PRIVILEGE_POLICY_ID_it;
}

static ATTR_DESC_TT: Templates<5> = Templates([
    template_at(
        0,
        0,
        offset_of!(OSSL_ATTRIBUTE_DESCRIPTOR, identifier),
        c"identifier",
        ASN1_OBJECT_it,
    ),
    template_at(
        0,
        0,
        offset_of!(OSSL_ATTRIBUTE_DESCRIPTOR, attributeSyntax),
        c"attributeSyntax",
        ASN1_OCTET_STRING_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(OSSL_ATTRIBUTE_DESCRIPTOR, name),
        c"name",
        ASN1_UTF8STRING_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(OSSL_ATTRIBUTE_DESCRIPTOR, description),
        c"description",
        ASN1_UTF8STRING_it,
    ),
    template_at(
        0,
        0,
        offset_of!(OSSL_ATTRIBUTE_DESCRIPTOR, dominationRule),
        c"dominationRule",
        OSSL_PRIVILEGE_POLICY_ID_it,
    ),
]);

item_fns! {
    /// An attribute descriptor: the identifier, the syntax, the optional [0] name and [1] description, and the domination rule.
    pub unsafe extern "C" fn OSSL_ATTRIBUTE_DESCRIPTOR_it = sequence::<OSSL_ATTRIBUTE_DESCRIPTOR, 5>(&ATTR_DESC_TT, None, c"OSSL_ATTRIBUTE_DESCRIPTOR");
}

new_free! {
    pub unsafe extern "C" fn OSSL_ATTRIBUTE_DESCRIPTOR_new, pub unsafe extern "C" fn OSSL_ATTRIBUTE_DESCRIPTOR_free(OSSL_ATTRIBUTE_DESCRIPTOR) = OSSL_ATTRIBUTE_DESCRIPTOR_it;
}

i2d! {
    /// Encodes an `OSSL_ATTRIBUTE_DESCRIPTOR`.
    pub unsafe extern "C" fn i2d_OSSL_ATTRIBUTE_DESCRIPTOR(OSSL_ATTRIBUTE_DESCRIPTOR) = OSSL_ATTRIBUTE_DESCRIPTOR_it;
}

d2i! {
    /// Decodes an `OSSL_ATTRIBUTE_DESCRIPTOR` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_ATTRIBUTE_DESCRIPTOR(OSSL_ATTRIBUTE_DESCRIPTOR) = OSSL_ATTRIBUTE_DESCRIPTOR_it;
}

static ATAV_TT: Templates<2> = Templates([
    template_at(0, 0, offset_of!(OSSL_ATAV, type_), c"type", ASN1_OBJECT_it),
    template_at(0, 0, offset_of!(OSSL_ATAV, value), c"value", ASN1_ANY_it),
]);

item_fns! {
    /// An attribute type and value.
    pub unsafe extern "C" fn OSSL_ATAV_it = sequence::<OSSL_ATAV, 2>(&ATAV_TT, None, c"OSSL_ATAV");
}

new_free! {
    pub unsafe extern "C" fn OSSL_ATAV_new, pub unsafe extern "C" fn OSSL_ATAV_free(OSSL_ATAV) = OSSL_ATAV_it;
}

i2d! {
    /// Encodes an `OSSL_ATAV`.
    pub unsafe extern "C" fn i2d_OSSL_ATAV(OSSL_ATAV) = OSSL_ATAV_it;
}

d2i! {
    /// Decodes an `OSSL_ATAV` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_ATAV(OSSL_ATAV) = OSSL_ATAV_it;
}

static TYPE_MAPPING_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_IMPLICIT,
        0,
        offset_of!(OSSL_ATTRIBUTE_TYPE_MAPPING, local),
        c"local",
        ASN1_OBJECT_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT,
        1,
        offset_of!(OSSL_ATTRIBUTE_TYPE_MAPPING, remote),
        c"remote",
        ASN1_OBJECT_it,
    ),
]);

item_fns! {
    /// An attribute type mapping: [0] local and [1] remote types.
    pub unsafe extern "C" fn OSSL_ATTRIBUTE_TYPE_MAPPING_it = sequence::<OSSL_ATTRIBUTE_TYPE_MAPPING, 2>(&TYPE_MAPPING_TT, None, c"OSSL_ATTRIBUTE_TYPE_MAPPING");
}

new_free! {
    pub unsafe extern "C" fn OSSL_ATTRIBUTE_TYPE_MAPPING_new, pub unsafe extern "C" fn OSSL_ATTRIBUTE_TYPE_MAPPING_free(OSSL_ATTRIBUTE_TYPE_MAPPING) = OSSL_ATTRIBUTE_TYPE_MAPPING_it;
}

i2d! {
    /// Encodes an `OSSL_ATTRIBUTE_TYPE_MAPPING`.
    pub unsafe extern "C" fn i2d_OSSL_ATTRIBUTE_TYPE_MAPPING(OSSL_ATTRIBUTE_TYPE_MAPPING) = OSSL_ATTRIBUTE_TYPE_MAPPING_it;
}

d2i! {
    /// Decodes an `OSSL_ATTRIBUTE_TYPE_MAPPING` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_ATTRIBUTE_TYPE_MAPPING(OSSL_ATTRIBUTE_TYPE_MAPPING) = OSSL_ATTRIBUTE_TYPE_MAPPING_it;
}

static VALUE_MAPPING_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_IMPLICIT,
        0,
        offset_of!(OSSL_ATTRIBUTE_VALUE_MAPPING, local),
        c"local",
        OSSL_ATAV_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT,
        1,
        offset_of!(OSSL_ATTRIBUTE_VALUE_MAPPING, remote),
        c"remote",
        OSSL_ATAV_it,
    ),
]);

item_fns! {
    /// An attribute value mapping: [0] local and [1] remote types and values.
    pub unsafe extern "C" fn OSSL_ATTRIBUTE_VALUE_MAPPING_it = sequence::<OSSL_ATTRIBUTE_VALUE_MAPPING, 2>(&VALUE_MAPPING_TT, None, c"OSSL_ATTRIBUTE_VALUE_MAPPING");
}

new_free! {
    pub unsafe extern "C" fn OSSL_ATTRIBUTE_VALUE_MAPPING_new, pub unsafe extern "C" fn OSSL_ATTRIBUTE_VALUE_MAPPING_free(OSSL_ATTRIBUTE_VALUE_MAPPING) = OSSL_ATTRIBUTE_VALUE_MAPPING_it;
}

i2d! {
    /// Encodes an `OSSL_ATTRIBUTE_VALUE_MAPPING`.
    pub unsafe extern "C" fn i2d_OSSL_ATTRIBUTE_VALUE_MAPPING(OSSL_ATTRIBUTE_VALUE_MAPPING) = OSSL_ATTRIBUTE_VALUE_MAPPING_it;
}

d2i! {
    /// Decodes an `OSSL_ATTRIBUTE_VALUE_MAPPING` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_ATTRIBUTE_VALUE_MAPPING(OSSL_ATTRIBUTE_VALUE_MAPPING) = OSSL_ATTRIBUTE_VALUE_MAPPING_it;
}

static MAPPING_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_IMPLICIT,
        OSSL_ATTR_MAP_TYPE as c_long,
        offset_of!(OSSL_ATTRIBUTE_MAPPING, choice),
        c"choice.typeMappings",
        OSSL_ATTRIBUTE_TYPE_MAPPING_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT,
        OSSL_ATTR_MAP_VALUE as c_long,
        offset_of!(OSSL_ATTRIBUTE_MAPPING, choice),
        c"choice.typeValueMappings",
        OSSL_ATTRIBUTE_VALUE_MAPPING_it,
    ),
]);

item_fns! {
    /// An attribute mapping: [0] of types or [1] of values.
    pub unsafe extern "C" fn OSSL_ATTRIBUTE_MAPPING_it = choice::<OSSL_ATTRIBUTE_MAPPING, 2>(&MAPPING_TT, offset_of!(OSSL_ATTRIBUTE_MAPPING, type_), None, c"OSSL_ATTRIBUTE_MAPPING");
}

new_free! {
    pub unsafe extern "C" fn OSSL_ATTRIBUTE_MAPPING_new, pub unsafe extern "C" fn OSSL_ATTRIBUTE_MAPPING_free(OSSL_ATTRIBUTE_MAPPING) = OSSL_ATTRIBUTE_MAPPING_it;
}

i2d! {
    /// Encodes an `OSSL_ATTRIBUTE_MAPPING`.
    pub unsafe extern "C" fn i2d_OSSL_ATTRIBUTE_MAPPING(OSSL_ATTRIBUTE_MAPPING) = OSSL_ATTRIBUTE_MAPPING_it;
}

d2i! {
    /// Decodes an `OSSL_ATTRIBUTE_MAPPING` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_ATTRIBUTE_MAPPING(OSSL_ATTRIBUTE_MAPPING) = OSSL_ATTRIBUTE_MAPPING_it;
}

static MAPPINGS_T: Template = template(
    ASN1_TFLG_SET_OF,
    0,
    c"OSSL_ATTRIBUTE_MAPPINGS",
    OSSL_ATTRIBUTE_MAPPING_it,
);

item_fns! {
    /// Attribute mappings: SET OF AttributeMapping.
    pub unsafe extern "C" fn OSSL_ATTRIBUTE_MAPPINGS_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const MAPPINGS_T.0, 0, ptr::null(), 0, c"OSSL_ATTRIBUTE_MAPPINGS");
}

new_free! {
    pub unsafe extern "C" fn OSSL_ATTRIBUTE_MAPPINGS_new, pub unsafe extern "C" fn OSSL_ATTRIBUTE_MAPPINGS_free(OSSL_ATTRIBUTE_MAPPINGS) = OSSL_ATTRIBUTE_MAPPINGS_it;
}

i2d! {
    /// Encodes an `OSSL_ATTRIBUTE_MAPPINGS`.
    pub unsafe extern "C" fn i2d_OSSL_ATTRIBUTE_MAPPINGS(OSSL_ATTRIBUTE_MAPPINGS) = OSSL_ATTRIBUTE_MAPPINGS_it;
}

d2i! {
    /// Decodes an `OSSL_ATTRIBUTE_MAPPINGS` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_ATTRIBUTE_MAPPINGS(OSSL_ATTRIBUTE_MAPPINGS) = OSSL_ATTRIBUTE_MAPPINGS_it;
}

static AA_CHOICE_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_IMPLICIT,
        OSSL_AAA_ATTRIBUTE_TYPE as c_long,
        offset_of!(OSSL_ALLOWED_ATTRIBUTES_CHOICE, choice),
        c"choice.attributeType",
        ASN1_OBJECT_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT,
        OSSL_AAA_ATTRIBUTE_VALUES as c_long,
        offset_of!(OSSL_ALLOWED_ATTRIBUTES_CHOICE, choice),
        c"choice.attributeTypeandValues",
        X509_ATTRIBUTE_it,
    ),
]);

item_fns! {
    /// An allowed attribute: [0] a type, or [1] a type and values.
    pub unsafe extern "C" fn OSSL_ALLOWED_ATTRIBUTES_CHOICE_it = choice::<OSSL_ALLOWED_ATTRIBUTES_CHOICE, 2>(&AA_CHOICE_TT, offset_of!(OSSL_ALLOWED_ATTRIBUTES_CHOICE, type_), None, c"OSSL_ALLOWED_ATTRIBUTES_CHOICE");
}

new_free! {
    pub unsafe extern "C" fn OSSL_ALLOWED_ATTRIBUTES_CHOICE_new, pub unsafe extern "C" fn OSSL_ALLOWED_ATTRIBUTES_CHOICE_free(OSSL_ALLOWED_ATTRIBUTES_CHOICE) = OSSL_ALLOWED_ATTRIBUTES_CHOICE_it;
}

i2d! {
    /// Encodes an `OSSL_ALLOWED_ATTRIBUTES_CHOICE`.
    pub unsafe extern "C" fn i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE(OSSL_ALLOWED_ATTRIBUTES_CHOICE) = OSSL_ALLOWED_ATTRIBUTES_CHOICE_it;
}

d2i! {
    /// Decodes an `OSSL_ALLOWED_ATTRIBUTES_CHOICE` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE(OSSL_ALLOWED_ATTRIBUTES_CHOICE) = OSSL_ALLOWED_ATTRIBUTES_CHOICE_it;
}

static AA_ITEM_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF,
        0,
        offset_of!(OSSL_ALLOWED_ATTRIBUTES_ITEM, attributes),
        c"attributes",
        OSSL_ALLOWED_ATTRIBUTES_CHOICE_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT,
        1,
        offset_of!(OSSL_ALLOWED_ATTRIBUTES_ITEM, holderDomain),
        c"holderDomain",
        GENERAL_NAME_it,
    ),
]);

item_fns! {
    /// Allowed attributes: [0] a SET OF them, and [1] the holder's domain.
    pub unsafe extern "C" fn OSSL_ALLOWED_ATTRIBUTES_ITEM_it = sequence::<OSSL_ALLOWED_ATTRIBUTES_ITEM, 2>(&AA_ITEM_TT, None, c"OSSL_ALLOWED_ATTRIBUTES_ITEM");
}

new_free! {
    pub unsafe extern "C" fn OSSL_ALLOWED_ATTRIBUTES_ITEM_new, pub unsafe extern "C" fn OSSL_ALLOWED_ATTRIBUTES_ITEM_free(OSSL_ALLOWED_ATTRIBUTES_ITEM) = OSSL_ALLOWED_ATTRIBUTES_ITEM_it;
}

i2d! {
    /// Encodes an `OSSL_ALLOWED_ATTRIBUTES_ITEM`.
    pub unsafe extern "C" fn i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM(OSSL_ALLOWED_ATTRIBUTES_ITEM) = OSSL_ALLOWED_ATTRIBUTES_ITEM_it;
}

d2i! {
    /// Decodes an `OSSL_ALLOWED_ATTRIBUTES_ITEM` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM(OSSL_ALLOWED_ATTRIBUTES_ITEM) = OSSL_ALLOWED_ATTRIBUTES_ITEM_it;
}

static AA_SYNTAX_T: Template = template(
    ASN1_TFLG_SET_OF,
    0,
    c"OSSL_ALLOWED_ATTRIBUTES_SYNTAX",
    OSSL_ALLOWED_ATTRIBUTES_ITEM_it,
);

item_fns! {
    /// Allowed attribute assignments: SET OF them.
    pub unsafe extern "C" fn OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const AA_SYNTAX_T.0, 0, ptr::null(), 0, c"OSSL_ALLOWED_ATTRIBUTES_SYNTAX");
}

new_free! {
    pub unsafe extern "C" fn OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new, pub unsafe extern "C" fn OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free(OSSL_ALLOWED_ATTRIBUTES_SYNTAX) = OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it;
}

i2d! {
    /// Encodes an `OSSL_ALLOWED_ATTRIBUTES_SYNTAX`.
    pub unsafe extern "C" fn i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX(OSSL_ALLOWED_ATTRIBUTES_SYNTAX) = OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it;
}

d2i! {
    /// Decodes an `OSSL_ALLOWED_ATTRIBUTES_SYNTAX` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX(OSSL_ALLOWED_ATTRIBUTES_SYNTAX) = OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it;
}

// Printing.

/// The values of a stack.
///
/// # Safety
/// `sk` is NULL or a live stack of `T`, which outlives the iterator.
unsafe fn values<'a, T: 'a>(sk: *const c_void) -> impl Iterator<Item = &'a mut T> {
    // SAFETY: the caller's guarantee.
    let n = unsafe { OPENSSL_sk_num(sk.cast()) };
    // SAFETY: an index within the stack.
    (0..n).filter_map(move |i| unsafe { item_at::<T>(sk, i) })
}

/// `i2r_HASH`: the algorithm, its parameter, and the hash value: positive if printed.
///
/// # Safety
/// `hash`'s parts are NULL or live.
unsafe fn hash_print(o: Out, hash: &OSSL_HASH, indent: c_int) -> c_int {
    let out = o.bio();
    // SAFETY: the caller's guarantee.
    let Some(alg) = (unsafe { hash.algorithmIdentifier.as_ref() }) else {
        return 0;
    };
    if o.line(indent, "Algorithm: ") <= 0 {
        return 0;
    }
    // SAFETY: the caller's BIO; its algorithm.
    if unsafe { i2a_ASN1_OBJECT(out, alg.algorithm) } <= 0 || o.print("\n") <= 0 {
        return 0;
    }
    if !alg.parameter.is_null() {
        if o.line(indent, "Parameter: ") <= 0 {
            return 0;
        }
        let ind = indent.saturating_add(4);
        // SAFETY: as above; its parameter.
        if unsafe { print_attribute_value(out, 0, alg.parameter, ind) } <= 0 {
            return 0;
        }
        if o.print("\n") <= 0 {
            return 0;
        }
    }
    if o.line(indent, "Hash Value: ") <= 0 {
        return 0;
    }
    // SAFETY: as above.
    let Some(v) = (unsafe { hash.hashValue.as_ref() }) else {
        return 0;
    };
    let n = usize::try_from(v.length).unwrap_or(0);
    let octets = if n == 0 || v.data.is_null() {
        &[][..]
    } else {
        // SAFETY: a string's data holds its length.
        unsafe { core::slice::from_raw_parts(v.data, n) }
    };
    bio_print_hex(o, octets)
}

/// `i2r_INFO_SYNTAX_POINTER`: the names, and the hash if there's one.
///
/// # Safety
/// `p`'s parts are NULL or live.
unsafe fn pointer_print(o: Out, p: &OSSL_INFO_SYNTAX_POINTER, indent: c_int) -> c_int {
    if o.line(indent, "Names:\n") <= 0 {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    if unsafe { OSSL_GENERAL_NAMES_print(o.bio(), p.name, indent) } <= 0 || o.print("\n") <= 0 {
        return 0;
    }
    // SAFETY: as above.
    if let Some(h) = unsafe { p.hash.as_ref() } {
        if o.line(indent, "Hash:\n") <= 0 {
            return 0;
        }
        // SAFETY: as above.
        if unsafe { hash_print(o, h, indent.saturating_add(4)) } <= 0 {
            return 0;
        }
    }
    1
}

/// `i2r_OSSL_INFO_SYNTAX`: the content, or the pointer.
///
/// # Safety
/// `info`'s member is live.
unsafe fn info_syntax_print(o: Out, info: &OSSL_INFO_SYNTAX, indent: c_int) -> c_int {
    match info.type_ {
        t if t == OSSL_INFO_SYNTAX_TYPE_CONTENT => {
            if o.line(indent, "Content: ") <= 0 {
                return 0;
            }
            // SAFETY: the choice's member.
            let content = unsafe { info.choice.content };
            // SAFETY: the caller's guarantee.
            if o.write(unsafe { precision_text(content) }) <= 0 || o.print("\n") <= 0 {
                return 0;
            }
            1
        }
        t if t == OSSL_INFO_SYNTAX_TYPE_POINTER => {
            if o.line(indent, "Pointer:\n") <= 0 {
                return 0;
            }
            // SAFETY: the choice's member.
            let p = unsafe { info.choice.pointer };
            // SAFETY: the caller's guarantee.
            match unsafe { p.as_ref() } {
                // SAFETY: as above.
                Some(p) => unsafe { pointer_print(o, p, indent.saturating_add(4)) },
                None => 0,
            }
        }
        _ => 0,
    }
}

/// `i2r_OSSL_PRIVILEGE_POLICY_ID`: the policy's OID and its syntax.
///
/// # Safety
/// `ppid`'s parts are NULL or live.
unsafe fn ppid_print(o: Out, ppid: &OSSL_PRIVILEGE_POLICY_ID, indent: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(oid) = (unsafe { oid_text80(ppid.privilegePolicy) }) else {
        return 0;
    };
    if o.line(indent, &format!("Privilege Policy Identifier: {oid}\n")) <= 0 {
        return 0;
    }
    if o.line(indent, "Privilege Policy Syntax:\n") <= 0 {
        return 0;
    }
    // SAFETY: as above.
    match unsafe { ppid.privPolSyntax.as_ref() } {
        // SAFETY: as above.
        Some(s) => unsafe { info_syntax_print(o, s, indent.saturating_add(4)) },
        None => 0,
    }
}

/// `"%*s<label>%.*s\n"` of a string.
///
/// # Safety
/// `s` is a live string.
unsafe fn labeled(
    o: Out,
    indent: c_int,
    label: &str,
    s: *const rustyssl_abi::ASN1_STRING,
) -> c_int {
    let mut text = label.as_bytes().to_vec();
    // SAFETY: the caller's guarantee.
    text.extend_from_slice(unsafe { precision_text(s) });
    text.push(b'\n');
    if o.line(indent, "") < 0 {
        return -1;
    }
    o.write(&text)
}

ffi_callback! {
    /// `i2r_OSSL_ATTRIBUTE_DESCRIPTOR`: the identifier, the syntax, the name and description
    /// if there are, and the domination rule.
    ///
    /// # Safety
    /// `ext` is a live `OSSL_ATTRIBUTE_DESCRIPTOR`; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn attr_desc_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let o = unsafe { Out::new(out) };
        // SAFETY: as above.
        let Some(ad) = (unsafe { ext.cast::<OSSL_ATTRIBUTE_DESCRIPTOR>().as_ref() }) else { return 0 };
        // SAFETY: its identifier.
        let Some(oid) = (unsafe { oid_text80(ad.identifier) }) else { return 0 };
        if o.line(indent, &format!("Identifier: {oid}\n")) <= 0 || o.line(indent, "Syntax:\n") <= 0 {
            return 0;
        }
        // SAFETY: its syntax.
        if unsafe { o.line_string(indent.saturating_add(4), ad.attributeSyntax) } <= 0 {
            return 0;
        }
        if o.print("\n\n") <= 0 {
            return 0;
        }
        // SAFETY: its name.
        if !ad.name.is_null() && unsafe { labeled(o, indent, "Name: ", ad.name) } <= 0 {
            return 0;
        }
        // SAFETY: its description.
        if !ad.description.is_null() && unsafe { labeled(o, indent, "Description: ", ad.description) } <= 0 {
            return 0;
        }
        if o.line(indent, "Domination Rule:\n") <= 0 {
            return 0;
        }
        // SAFETY: its rule.
        match unsafe { ad.dominationRule.as_ref() } {
            // SAFETY: as above.
            Some(r) => unsafe { ppid_print(o, r, indent.saturating_add(4)) },
            None => 0,
        }
    }
}

pub(crate) static ATTRIBUTE_DESCRIPTOR: Method = Method({
    let mut m = method(NID_attribute_descriptor, X509V3_EXT_MULTILINE);
    m.it = Some(OSSL_ATTRIBUTE_DESCRIPTOR_it);
    m.i2r = Some(attr_desc_i2r);
    m
});

/// A type and value of a mapping: `type:value`.
///
/// # Safety
/// `atav`'s parts are NULL or live.
unsafe fn atav_print(o: Out, atav: *const OSSL_ATAV) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(a) = (unsafe { atav.as_ref() }) else {
        return 0;
    };
    // SAFETY: as above.
    let nid = unsafe { OBJ_obj2nid(a.type_) };
    // SAFETY: as above.
    if unsafe { i2a_ASN1_OBJECT(o.bio(), a.type_) } <= 0 || o.print(":") <= 0 {
        return 0;
    }
    // SAFETY: as above.
    unsafe { print_attribute_value(o.bio(), nid, a.value, 0) }
}

/// `i2r_ATTRIBUTE_MAPPING`: `local == remote`, of types or of types and values.
///
/// # Safety
/// `am`'s parts are NULL or live.
unsafe fn mapping_print(o: Out, am: &OSSL_ATTRIBUTE_MAPPING) -> c_int {
    let out = o.bio();
    match am.type_ {
        t if t == OSSL_ATTR_MAP_TYPE => {
            // SAFETY: the choice's member.
            let tm = unsafe { am.choice.typeMappings };
            // SAFETY: the caller's guarantee.
            let Some(tm) = (unsafe { tm.cast_const().as_ref() }) else {
                return 0;
            };
            let tm: &OSSL_ATTRIBUTE_TYPE_MAPPING = tm;
            // SAFETY: as above.
            if unsafe { i2a_ASN1_OBJECT(out, tm.local) } <= 0 || o.print(" == ") <= 0 {
                return 0;
            }
            // SAFETY: as above.
            unsafe { i2a_ASN1_OBJECT(out, tm.remote) }
        }
        t if t == OSSL_ATTR_MAP_VALUE => {
            // SAFETY: the choice's member.
            let vm = unsafe { am.choice.typeValueMappings };
            // SAFETY: the caller's guarantee.
            let Some(vm) = (unsafe { vm.cast_const().as_ref() }) else {
                return 0;
            };
            let vm: &OSSL_ATTRIBUTE_VALUE_MAPPING = vm;
            // SAFETY: as above.
            if unsafe { atav_print(o, vm.local) } <= 0 || o.print(" == ") <= 0 {
                return 0;
            }
            // SAFETY: as above.
            unsafe { atav_print(o, vm.remote) }
        }
        _ => 0,
    }
}

ffi_callback! {
    /// `i2r_ATTRIBUTE_MAPPINGS`: each mapping on a line; nothing, and 0, at no indent
    /// (OpenSSL's check of its indent's write).
    ///
    /// # Safety
    /// `ext` is a live `OSSL_ATTRIBUTE_MAPPINGS`; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn mappings_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let o = unsafe { Out::new(out) };
        // SAFETY: as above.
        for am in unsafe { values::<OSSL_ATTRIBUTE_MAPPING>(ext) } {
            if o.line(indent, "") <= 0 {
                return 0;
            }
            // SAFETY: a mapping of the stack.
            if unsafe { mapping_print(o, am) } <= 0 || o.print("\n") <= 0 {
                return 0;
            }
        }
        1
    }
}

pub(crate) static ATTRIBUTE_MAPPINGS: Method = Method({
    let mut m = method(NID_attribute_mappings, X509V3_EXT_MULTILINE);
    m.it = Some(OSSL_ATTRIBUTE_MAPPINGS_it);
    m.i2r = Some(mappings_i2r);
    m
});

/// `i2r_ALLOWED_ATTRIBUTES_CHOICE`: the type, or the type and each value.
///
/// # Safety
/// `a`'s member is live.
unsafe fn aa_choice_print(o: Out, a: &OSSL_ALLOWED_ATTRIBUTES_CHOICE, indent: c_int) -> c_int {
    let out = o.bio();
    match a.type_ {
        t if t == OSSL_AAA_ATTRIBUTE_TYPE => {
            if o.line(indent, "Attribute Type: ") <= 0 {
                return 0;
            }
            // SAFETY: the choice's member.
            let obj = unsafe { a.choice.attributeType };
            // SAFETY: the caller's guarantee.
            if unsafe { i2a_ASN1_OBJECT(out, obj) } <= 0 {
                return 0;
            }
            c_int::from(o.print("\n") > 0)
        }
        t if t == OSSL_AAA_ATTRIBUTE_VALUES => {
            // SAFETY: the choice's member.
            let attr = unsafe { a.choice.attributeTypeandValues };
            // SAFETY: the caller's guarantee.
            let obj = unsafe { X509_ATTRIBUTE_get0_object(attr) };
            // SAFETY: its type.
            let nid = unsafe { OBJ_obj2nid(obj) };
            if o.line(indent, "Attribute Values: ") <= 0 {
                return 0;
            }
            // SAFETY: as above.
            if unsafe { i2a_ASN1_OBJECT(out, obj) } <= 0 || o.print("\n") <= 0 {
                return 0;
            }
            // SAFETY: as above.
            let count = unsafe { X509_ATTRIBUTE_count(attr) };
            for j in 0..count {
                // SAFETY: as above; an index within its values.
                let av = unsafe { X509_ATTRIBUTE_get0_type(attr, j) };
                // SAFETY: as above; its value.
                if unsafe { print_attribute_value(out, nid, av, indent.saturating_add(4)) } <= 0 {
                    return 0;
                }
                if o.print("\n") <= 0 {
                    return 0;
                }
            }
            1
        }
        _ => 0,
    }
}

/// `i2r_ALLOWED_ATTRIBUTES_ITEM`: each allowed attribute, then the holder's domain.
///
/// # Safety
/// `aai`'s parts are NULL or live.
unsafe fn aa_item_print(o: Out, aai: &OSSL_ALLOWED_ATTRIBUTES_ITEM, indent: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    for a in unsafe { values::<OSSL_ALLOWED_ATTRIBUTES_CHOICE>(aai.attributes.cast()) } {
        if o.line(indent, "Allowed Attribute Type or Values:\n") <= 0 {
            return 0;
        }
        // SAFETY: an allowed attribute of the stack.
        if unsafe { aa_choice_print(o, a, indent.saturating_add(4)) } <= 0 {
            return 0;
        }
    }
    if o.line(indent, "Holder Domain: ") <= 0 {
        return 0;
    }
    // SAFETY: as above.
    if unsafe { GENERAL_NAME_print(o.bio(), aai.holderDomain) } <= 0 || o.print("\n") <= 0 {
        return 0;
    }
    1
}

ffi_callback! {
    /// `i2r_ALLOWED_ATTRIBUTES_SYNTAX`: each set of allowed attributes.
    ///
    /// # Safety
    /// `ext` is a live `OSSL_ALLOWED_ATTRIBUTES_SYNTAX`; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn aaa_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let o = unsafe { Out::new(out) };
        // SAFETY: as above.
        for aai in unsafe { values::<OSSL_ALLOWED_ATTRIBUTES_ITEM>(ext) } {
            if o.line(indent, "Allowed Attributes:\n") <= 0 {
                return 0;
            }
            // SAFETY: an item of the stack.
            if unsafe { aa_item_print(o, aai, indent.saturating_add(4)) } <= 0 {
                return 0;
            }
        }
        1
    }
}

pub(crate) static ALLOWED_ATTRIBUTE_ASSIGNMENTS: Method = Method({
    let mut m = method(NID_allowed_attribute_assignments, 0);
    m.it = Some(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it);
    m.i2r = Some(aaa_i2r);
    m
});
