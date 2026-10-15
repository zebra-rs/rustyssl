//! EC parameters' ASN.1 (`ec_asn1.c`, `eck_prn.c`): the `ECPARAMETERS` and `ECPKPARAMETERS`
//! structures with OpenSSL's private layouts and templates (and those of `X9_62_FIELDID`,
//! `X9_62_CHARACTERISTIC_TWO`, `X9_62_PENTANOMIAL`, and `X9_62_CURVE`, which it doesn't
//! export), a group's conversions to and from them, `d2i_`/`i2d_ECPKParameters`, and
//! `ECPKParameters_print`.
//!
//! The conversions go through the public group and point functions in OpenSSL's order, so they
//! raise its errors. Where OpenSSL's are unsafe, these aren't (docs/DEVIATIONS.md): an existing
//! `ECPARAMETERS` has its field parameters freed as the type they are, an existing
//! `ECPKPARAMETERS` isn't freed when the conversion fails, and NULL structures are refused.

use core::ffi::{CStr, c_int, c_long, c_uchar, c_void};
use core::mem::offset_of;
use core::ptr;

use libc::FILE;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_INTEGER, ASN1_ITEM, ASN1_OBJECT, ASN1_OCTET_STRING,
    ASN1_STRING_FLAG_BITS_LEFT, ASN1_TFLG_EMBED, ASN1_TFLG_OPTIONAL, BIGNUM, BIO, BIO_NOCLOSE,
    EC_GROUP, EC_POINT, EC_R_ASN1_ERROR, EC_R_EC_GROUP_NEW_BY_NAME_FAILURE, EC_R_FIELD_TOO_LARGE,
    EC_R_GROUP2PKPARAMETERS_FAILURE, EC_R_I2D_ECPKPARAMETERS_FAILURE, EC_R_INVALID_FIELD,
    EC_R_INVALID_GROUP_ORDER, EC_R_INVALID_PENTANOMIAL_BASIS, EC_R_INVALID_TRINOMIAL_BASIS,
    EC_R_MISSING_OID, EC_R_MISSING_PARAMETERS, EC_R_NOT_IMPLEMENTED, EC_R_UNDEFINED_GENERATOR,
    EC_R_UNSUPPORTED_FIELD, ECPARAMETERS, ECPKPARAMETERS, ERR_LIB_ASN1, ERR_LIB_EC, ERR_R_ASN1_LIB,
    ERR_R_BIO_LIB, ERR_R_BN_LIB, ERR_R_BUF_LIB, ERR_R_EC_LIB, ERR_R_OBJ_LIB,
    ERR_R_PASSED_NULL_PARAMETER, NID_X9_62_characteristic_two_field, NID_X9_62_onBasis,
    NID_X9_62_ppBasis, NID_X9_62_prime_field, NID_X9_62_tpBasis, NID_secp224r1, NID_undef,
    NID_wap_wsg_idm_ecid_wtls12, OPENSSL_EC_EXPLICIT_CURVE, OPENSSL_EC_NAMED_CURVE,
    OPENSSL_ECC_MAX_FIELD_BITS, POINT_CONVERSION_COMPRESSED, POINT_CONVERSION_UNCOMPRESSED,
    point_conversion_form_t,
};
use rustyssl_crypto::ec::curves::{self, Method};

use super::curves::EC_curve_nid2nist;
use super::group::{
    EC_GROUP_dup, EC_GROUP_free, EC_GROUP_get_asn1_flag, EC_GROUP_get_basis_type,
    EC_GROUP_get_curve, EC_GROUP_get_curve_name, EC_GROUP_get_degree, EC_GROUP_get_field_type,
    EC_GROUP_get_pentanomial_basis, EC_GROUP_get_point_conversion_form, EC_GROUP_get_seed_len,
    EC_GROUP_get_trinomial_basis, EC_GROUP_get0_cofactor, EC_GROUP_get0_generator,
    EC_GROUP_get0_order, EC_GROUP_get0_seed, EC_GROUP_new_by_curve_name, EC_GROUP_new_curve_GF2m,
    EC_GROUP_new_curve_GFp, EC_GROUP_set_asn1_flag, EC_GROUP_set_generator,
    EC_GROUP_set_point_conversion_form, EC_GROUP_set_seed, curve_nid_from_params,
    set_decoded_from_explicit,
};
use super::point::{EC_POINT_free, EC_POINT_new, EC_POINT_oct2point, EC_POINT_point2buf};
use crate::asn1::bit_string::ASN1_BIT_STRING_set;
use crate::asn1::integer::{ASN1_INTEGER_get, ASN1_INTEGER_set};
use crate::asn1::string::{
    ASN1_BIT_STRING_new, ASN1_INTEGER_free, ASN1_INTEGER_new, ASN1_OCTET_STRING_new,
    ASN1_OCTET_STRING_set, ASN1_STRING_free, ASN1_STRING_set0,
};
use crate::asn1::tpl::decode::ASN1_item_d2i;
use crate::asn1::tpl::encode::ASN1_item_i2d;
use crate::asn1::tpl::free::ASN1_item_free;
use crate::asn1::tpl::ints::INT32_it;
use crate::asn1::tpl::items::{
    ASN1_ANY_it, ASN1_BIT_STRING_it, ASN1_INTEGER_it, ASN1_NULL_it, ASN1_NULL_new, ASN1_OBJECT_it,
    ASN1_OCTET_STRING_it, ASN1_TYPE_free, new_free,
};
use crate::asn1::tpl::new::ASN1_item_new;
use crate::asn1::tpl::statics::{
    Adb, AdbEntries, Templates, adb_entry, adb_object, adb_oid, choice, sequence,
};
use crate::asn1::tpl::{Item, Template, item_fns, template_at};
use crate::bio::print::BIO_printf;
use crate::bio::{BIO_free, BIO_indent, BIO_write};
use crate::bn::conv::{ASN1_INTEGER_to_BN, ASN1_bn_print, BN_bin2bn, BN_to_ASN1_INTEGER};
use crate::bn::{BN_free, BN_is_negative, BN_is_zero, BN_new, BN_num_bits, BN_set_bit};
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::{ASN1_OBJECT_free, OBJ_length, OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid};

/// `X9_62_PENTANOMIAL`.
#[repr(C)]
struct Pentanomial {
    k1: i32,
    k2: i32,
    k3: i32,
}

/// `X9_62_CHARACTERISTIC_TWO`: `p` is the basis' parameters, as `type` selects them.
#[repr(C)]
struct CharTwo {
    m: i32,
    kind: *mut ASN1_OBJECT,
    p: *mut c_void,
}

/// `X9_62_FIELDID`: `p` is the field's parameters, as `fieldType` selects them.
#[repr(C)]
struct FieldId {
    field_type: *mut ASN1_OBJECT,
    p: *mut c_void,
}

/// `X9_62_CURVE`.
#[repr(C)]
struct Curve {
    a: *mut ASN1_OCTET_STRING,
    b: *mut ASN1_OCTET_STRING,
    seed: *mut ASN1_BIT_STRING,
}

/// `ECPARAMETERS` (`struct ec_parameters_st`).
#[repr(C)]
struct Params {
    version: i32,
    field_id: *mut FieldId,
    curve: *mut Curve,
    base: *mut ASN1_OCTET_STRING,
    order: *mut ASN1_INTEGER,
    cofactor: *mut ASN1_INTEGER,
}

/// `ECPKPARAMETERS` (`struct ecpk_parameters_st`): `value` is a named curve's object, the
/// explicit `ECPARAMETERS`, or implicitlyCA's NULL, as `type` says.
#[repr(C)]
struct PkParams {
    kind: c_int,
    value: *mut c_void,
}

/// `ECPKPARAMETERS_TYPE_NAMED`, `_EXPLICIT`, and `_IMPLICIT`.
const TYPE_NAMED: c_int = 0;
const TYPE_EXPLICIT: c_int = 1;
const TYPE_IMPLICIT: c_int = 2;

static PENTANOMIAL_TT: Templates<3> = Templates([
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Pentanomial, k1),
        c"k1",
        INT32_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Pentanomial, k2),
        c"k2",
        INT32_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Pentanomial, k3),
        c"k3",
        INT32_it,
    ),
]);
static PENTANOMIAL: Item = sequence::<Pentanomial, 3>(&PENTANOMIAL_TT, None, c"X9_62_PENTANOMIAL");

/// `X9_62_PENTANOMIAL_it`, which OpenSSL doesn't export.
unsafe extern "C" fn pentanomial_it() -> *const ASN1_ITEM {
    &raw const PENTANOMIAL.0
}

static CHAR_TWO_DEFAULT: Template = Template(template_at(
    0,
    0,
    offset_of!(CharTwo, p),
    c"p.other",
    ASN1_ANY_it,
));
static CHAR_TWO_ENTRIES: AdbEntries<3> = AdbEntries([
    adb_entry(
        NID_X9_62_onBasis,
        template_at(0, 0, offset_of!(CharTwo, p), c"p.onBasis", ASN1_NULL_it),
    ),
    adb_entry(
        NID_X9_62_tpBasis,
        template_at(0, 0, offset_of!(CharTwo, p), c"p.tpBasis", ASN1_INTEGER_it),
    ),
    adb_entry(
        NID_X9_62_ppBasis,
        template_at(0, 0, offset_of!(CharTwo, p), c"p.ppBasis", pentanomial_it),
    ),
]);
static CHAR_TWO_ADB: Adb = adb_oid(
    offset_of!(CharTwo, kind),
    &CHAR_TWO_ENTRIES,
    &CHAR_TWO_DEFAULT,
);

/// The basis' table, in place of an item.
unsafe extern "C" fn char_two_adb() -> *const ASN1_ITEM {
    (&raw const CHAR_TWO_ADB.0).cast()
}

static CHAR_TWO_TT: Templates<3> = Templates([
    template_at(ASN1_TFLG_EMBED, 0, offset_of!(CharTwo, m), c"m", INT32_it),
    template_at(0, 0, offset_of!(CharTwo, kind), c"type", ASN1_OBJECT_it),
    adb_object(c"X9_62_CHARACTERISTIC_TWO", char_two_adb),
]);
static CHAR_TWO: Item = sequence::<CharTwo, 3>(&CHAR_TWO_TT, None, c"X9_62_CHARACTERISTIC_TWO");

/// `X9_62_CHARACTERISTIC_TWO_it`, which OpenSSL doesn't export.
unsafe extern "C" fn char_two_it() -> *const ASN1_ITEM {
    &raw const CHAR_TWO.0
}

static FIELD_ID_DEFAULT: Template = Template(template_at(
    0,
    0,
    offset_of!(FieldId, p),
    c"p.other",
    ASN1_ANY_it,
));
static FIELD_ID_ENTRIES: AdbEntries<2> = AdbEntries([
    adb_entry(
        NID_X9_62_prime_field,
        template_at(0, 0, offset_of!(FieldId, p), c"p.prime", ASN1_INTEGER_it),
    ),
    adb_entry(
        NID_X9_62_characteristic_two_field,
        template_at(0, 0, offset_of!(FieldId, p), c"p.char_two", char_two_it),
    ),
]);
static FIELD_ID_ADB: Adb = adb_oid(
    offset_of!(FieldId, field_type),
    &FIELD_ID_ENTRIES,
    &FIELD_ID_DEFAULT,
);

/// The field's table, in place of an item.
unsafe extern "C" fn field_id_adb() -> *const ASN1_ITEM {
    (&raw const FIELD_ID_ADB.0).cast()
}

static FIELD_ID_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(FieldId, field_type),
        c"fieldType",
        ASN1_OBJECT_it,
    ),
    adb_object(c"X9_62_FIELDID", field_id_adb),
]);
static FIELD_ID: Item = sequence::<FieldId, 2>(&FIELD_ID_TT, None, c"X9_62_FIELDID");

/// `X9_62_FIELDID_it`, which OpenSSL doesn't export.
unsafe extern "C" fn field_id_it() -> *const ASN1_ITEM {
    &raw const FIELD_ID.0
}

static CURVE_TT: Templates<3> = Templates([
    template_at(0, 0, offset_of!(Curve, a), c"a", ASN1_OCTET_STRING_it),
    template_at(0, 0, offset_of!(Curve, b), c"b", ASN1_OCTET_STRING_it),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(Curve, seed),
        c"seed",
        ASN1_BIT_STRING_it,
    ),
]);
static CURVE: Item = sequence::<Curve, 3>(&CURVE_TT, None, c"X9_62_CURVE");

/// `X9_62_CURVE_it`, which OpenSSL doesn't export.
unsafe extern "C" fn curve_it() -> *const ASN1_ITEM {
    &raw const CURVE.0
}

static PARAMS_TT: Templates<6> = Templates([
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Params, version),
        c"version",
        INT32_it,
    ),
    template_at(0, 0, offset_of!(Params, field_id), c"fieldID", field_id_it),
    template_at(0, 0, offset_of!(Params, curve), c"curve", curve_it),
    template_at(
        0,
        0,
        offset_of!(Params, base),
        c"base",
        ASN1_OCTET_STRING_it,
    ),
    template_at(0, 0, offset_of!(Params, order), c"order", ASN1_INTEGER_it),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(Params, cofactor),
        c"cofactor",
        ASN1_INTEGER_it,
    ),
]);

static PK_TT: Templates<3> = Templates([
    template_at(
        0,
        0,
        offset_of!(PkParams, value),
        c"value.named_curve",
        ASN1_OBJECT_it,
    ),
    template_at(
        0,
        0,
        offset_of!(PkParams, value),
        c"value.parameters",
        ECPARAMETERS_it,
    ),
    template_at(
        0,
        0,
        offset_of!(PkParams, value),
        c"value.implicitlyCA",
        ASN1_NULL_it,
    ),
]);

item_fns! {
    /// ECParameters: SEQUENCE { version, fieldID, curve, base, order, cofactor OPTIONAL }.
    pub unsafe extern "C" fn ECPARAMETERS_it = sequence::<Params, 6>(&PARAMS_TT, None, c"ECPARAMETERS");
    /// ECPKParameters: CHOICE { namedCurve OBJECT, explicit ECParameters, implicitlyCA NULL }.
    pub unsafe extern "C" fn ECPKPARAMETERS_it = choice::<PkParams, 3>(&PK_TT, offset_of!(PkParams, kind), None, c"ECPKPARAMETERS");
}

new_free! {
    pub unsafe extern "C" fn ECPARAMETERS_new, pub unsafe extern "C" fn ECPARAMETERS_free(ECPARAMETERS) = ECPARAMETERS_it;
    pub unsafe extern "C" fn ECPKPARAMETERS_new, pub unsafe extern "C" fn ECPKPARAMETERS_free(ECPKPARAMETERS) = ECPKPARAMETERS_it;
}

/// Raises an EC error from `func`.
fn raise(reason: c_int, func: &'static str) {
    err::raise(ERR_LIB_EC, reason, func);
}

/// Frees a field's parameters as the type its old `fieldType` made them.
///
/// # Safety
/// `field` is a live `X9_62_FIELDID`.
unsafe fn clear_field(field: *mut FieldId) {
    // SAFETY: the caller's guarantee.
    let f = unsafe { &mut *field };
    // SAFETY: NULL or a live object.
    let nid = unsafe { OBJ_obj2nid(f.field_type) };
    // SAFETY: as above, freed once.
    unsafe { ASN1_OBJECT_free(f.field_type) };
    f.field_type = ptr::null_mut();
    let p = core::mem::replace(&mut f.p, ptr::null_mut());
    if p.is_null() {
        return;
    }
    if nid == NID_X9_62_prime_field {
        // SAFETY: the prime field's parameter, an INTEGER.
        unsafe { ASN1_INTEGER_free(p.cast()) };
    } else if nid == NID_X9_62_characteristic_two_field {
        // SAFETY: the binary field's parameters.
        unsafe { ASN1_item_free(p.cast(), &raw const CHAR_TWO.0) };
    } else {
        // SAFETY: any other field's parameters, an ANY.
        unsafe { ASN1_TYPE_free(p.cast()) };
    }
}

/// `ec_asn1_group2fieldid`.
///
/// # Safety
/// `group` is a live group; `field` is NULL or a live `X9_62_FIELDID`.
unsafe fn group2fieldid(group: *const EC_GROUP, field: *mut FieldId) -> bool {
    const F: &str = "ec_asn1_group2fieldid";
    if field.is_null() {
        return false;
    }
    // SAFETY: the caller's guarantee.
    unsafe { clear_field(field) };
    // SAFETY: as above.
    let f = unsafe { &mut *field };
    // SAFETY: a live group.
    let nid = unsafe { EC_GROUP_get_field_type(group) };
    // SAFETY: no preconditions.
    f.field_type = unsafe { OBJ_nid2obj(nid) };
    if f.field_type.is_null() {
        raise(ERR_R_OBJ_LIB, F);
        return false;
    }
    if nid == NID_X9_62_prime_field {
        // SAFETY: no preconditions.
        let tmp = unsafe { BN_new() };
        if tmp.is_null() {
            raise(ERR_R_BN_LIB, F);
            return false;
        }
        // SAFETY: a live group and number.
        let ok = unsafe {
            EC_GROUP_get_curve(
                group,
                tmp,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        } != 0;
        let ok = ok || {
            raise(ERR_R_EC_LIB, F);
            false
        };
        if ok {
            // SAFETY: a live number.
            f.p = unsafe { BN_to_ASN1_INTEGER(tmp, ptr::null_mut()) }.cast();
        }
        // SAFETY: the number made above.
        unsafe { BN_free(tmp) };
        if !ok {
            return false;
        }
        if f.p.is_null() {
            raise(ERR_R_ASN1_LIB, F);
            return false;
        }
        return true;
    }
    if nid != NID_X9_62_characteristic_two_field {
        raise(EC_R_UNSUPPORTED_FIELD, F);
        return false;
    }
    // SAFETY: the item's own type.
    let ct: *mut CharTwo = unsafe { ASN1_item_new(&raw const CHAR_TWO.0) }.cast();
    f.p = ct.cast();
    if ct.is_null() {
        raise(ERR_R_ASN1_LIB, F);
        return false;
    }
    // SAFETY: just made.
    let c = unsafe { &mut *ct };
    // SAFETY: a live group.
    c.m = unsafe { EC_GROUP_get_degree(group) };
    // SAFETY: as above.
    let basis = unsafe { EC_GROUP_get_basis_type(group) };
    if basis == 0 {
        raise(ERR_R_EC_LIB, F);
        return false;
    }
    // SAFETY: no preconditions.
    c.kind = unsafe { OBJ_nid2obj(basis) };
    if c.kind.is_null() {
        raise(ERR_R_OBJ_LIB, F);
        return false;
    }
    if basis == NID_X9_62_tpBasis {
        let mut k = 0;
        // SAFETY: a live group; a local.
        if unsafe { EC_GROUP_get_trinomial_basis(group, &raw mut k) } == 0 {
            return false;
        }
        // SAFETY: no preconditions.
        let i = unsafe { ASN1_INTEGER_new() };
        c.p = i.cast();
        if i.is_null() {
            raise(ERR_R_ASN1_LIB, F);
            return false;
        }
        // SAFETY: just made.
        if unsafe { ASN1_INTEGER_set(i, c_long::from(k)) } == 0 {
            raise(ERR_R_ASN1_LIB, F);
            return false;
        }
    } else if basis == NID_X9_62_ppBasis {
        let (mut k1, mut k2, mut k3) = (0, 0, 0);
        // SAFETY: a live group; locals.
        let got =
            unsafe { EC_GROUP_get_pentanomial_basis(group, &raw mut k1, &raw mut k2, &raw mut k3) };
        if got == 0 {
            return false;
        }
        // SAFETY: the item's own type.
        let pp: *mut Pentanomial = unsafe { ASN1_item_new(&raw const PENTANOMIAL.0) }.cast();
        c.p = pp.cast();
        if pp.is_null() {
            raise(ERR_R_ASN1_LIB, F);
            return false;
        }
        // SAFETY: just made.
        let pv = unsafe { &mut *pp };
        // The degrees are below `OPENSSL_ECC_MAX_FIELD_BITS`.
        pv.k1 = i32::try_from(k1).unwrap_or(i32::MAX);
        pv.k2 = i32::try_from(k2).unwrap_or(i32::MAX);
        pv.k3 = i32::try_from(k3).unwrap_or(i32::MAX);
    } else {
        // SAFETY: no preconditions.
        c.p = unsafe { ASN1_NULL_new() }.cast();
        if c.p.is_null() {
            raise(ERR_R_ASN1_LIB, F);
            return false;
        }
    }
    true
}

/// `ec_asn1_group2curve`.
///
/// # Safety
/// `group` is a live group; `curve` is NULL or a live `X9_62_CURVE`.
unsafe fn group2curve(group: *const EC_GROUP, curve: *mut Curve) -> bool {
    const F: &str = "ec_asn1_group2curve";
    if curve.is_null() {
        return false;
    }
    // SAFETY: the caller's guarantee.
    let c = unsafe { &mut *curve };
    if c.a.is_null() || c.b.is_null() {
        return false;
    }
    // SAFETY: no preconditions.
    let (a, b) = (unsafe { BN_new() }, unsafe { BN_new() });
    let ok = (|| {
        if a.is_null() || b.is_null() {
            raise(ERR_R_BN_LIB, F);
            return false;
        }
        // SAFETY: a live group and numbers.
        if unsafe { EC_GROUP_get_curve(group, ptr::null_mut(), a, b, ptr::null_mut()) } == 0 {
            raise(ERR_R_EC_LIB, F);
            return false;
        }
        // SAFETY: a live group.
        let degree = usize::try_from(unsafe { EC_GROUP_get_degree(group) }).unwrap_or(0);
        let len = degree.saturating_add(7) / 8;
        // SAFETY: live numbers.
        let (av, bv) = (unsafe { crate::bn::value(a) }, unsafe {
            crate::bn::value(b)
        });
        let pad = |v: Option<rustyssl_crypto::bn::BigNum>| {
            v.and_then(|n| n.to_bin(Some(len), rustyssl_crypto::bn::Endian::Big, false))
        };
        let (Some(ab), Some(bb)) = (pad(av), pad(bv)) else {
            raise(ERR_R_BN_LIB, F);
            return false;
        };
        let Ok(l) = c_int::try_from(len) else {
            raise(ERR_R_ASN1_LIB, F);
            return false;
        };
        // SAFETY: live strings; buffers of `len` octets.
        let set = unsafe { ASN1_OCTET_STRING_set(c.a, ab.as_ptr(), l) } != 0
            // SAFETY: as above.
            && unsafe { ASN1_OCTET_STRING_set(c.b, bb.as_ptr(), l) } != 0;
        if !set {
            raise(ERR_R_ASN1_LIB, F);
            return false;
        }
        // SAFETY: a live group.
        let seed = unsafe { EC_GROUP_get0_seed(group) };
        if seed.is_null() {
            // SAFETY: NULL or the curve's own seed, freed once.
            unsafe { ASN1_STRING_free(c.seed) };
            c.seed = ptr::null_mut();
            return true;
        }
        if c.seed.is_null() {
            // SAFETY: no preconditions.
            c.seed = unsafe { ASN1_BIT_STRING_new() };
            if c.seed.is_null() {
                raise(ERR_R_ASN1_LIB, F);
                return false;
            }
        }
        // `ossl_asn1_string_set_bits_left(seed, 0)`.
        // SAFETY: a live string.
        let s = unsafe { &mut *c.seed };
        s.flags &= !0x07;
        s.flags |= c_long::from(ASN1_STRING_FLAG_BITS_LEFT);
        // SAFETY: a live group.
        let seed_len = c_int::try_from(unsafe { EC_GROUP_get_seed_len(group) }).unwrap_or(-1);
        // SAFETY: a live string; the group's seed of that length.
        if unsafe { ASN1_BIT_STRING_set(c.seed, seed, seed_len) } == 0 {
            raise(ERR_R_ASN1_LIB, F);
            return false;
        }
        true
    })();
    // SAFETY: the numbers made above, or NULL.
    unsafe { BN_free(a) };
    // SAFETY: as above.
    unsafe { BN_free(b) };
    ok
}

/// `EC_GROUP_get_ecparameters`' work into `ret`.
///
/// # Safety
/// `group` is a live group; `ret` is a live `ECPARAMETERS`.
unsafe fn fill_ecparameters(group: *const EC_GROUP, ret: *mut Params) -> bool {
    const F: &str = "EC_GROUP_get_ecparameters";
    // SAFETY: the caller's guarantee.
    let r = unsafe { &mut *ret };
    r.version = 1;
    // SAFETY: a live group; the structure's field.
    if !unsafe { group2fieldid(group, r.field_id) } {
        raise(ERR_R_EC_LIB, F);
        return false;
    }
    // SAFETY: as above.
    if !unsafe { group2curve(group, r.curve) } {
        raise(ERR_R_EC_LIB, F);
        return false;
    }
    // SAFETY: a live group.
    let point = unsafe { EC_GROUP_get0_generator(group) };
    if point.is_null() {
        raise(EC_R_UNDEFINED_GENERATOR, F);
        return false;
    }
    // SAFETY: as above.
    let form = unsafe { EC_GROUP_get_point_conversion_form(group) };
    let mut buffer: *mut c_uchar = ptr::null_mut();
    // SAFETY: the group and its generator; a local.
    let len = unsafe { EC_POINT_point2buf(group, point, form, &raw mut buffer, ptr::null_mut()) };
    if len == 0 {
        raise(ERR_R_EC_LIB, F);
        return false;
    }
    if r.base.is_null() {
        // SAFETY: no preconditions.
        r.base = unsafe { ASN1_OCTET_STRING_new() };
        if r.base.is_null() {
            // SAFETY: the encoding made above.
            unsafe { mem::release(buffer.cast()) };
            raise(ERR_R_ASN1_LIB, F);
            return false;
        }
    }
    // A point's encoding is far shorter than `INT_MAX`.
    let len = c_int::try_from(len).unwrap_or(c_int::MAX);
    // SAFETY: a live string, taking the encoding.
    unsafe { ASN1_STRING_set0(r.base, buffer.cast(), len) };
    // SAFETY: a live group.
    let order = unsafe { EC_GROUP_get0_order(group) };
    if order.is_null() {
        raise(ERR_R_EC_LIB, F);
        return false;
    }
    let orig = r.order;
    // SAFETY: a live number; the structure's INTEGER or NULL.
    r.order = unsafe { BN_to_ASN1_INTEGER(order, orig) };
    if r.order.is_null() {
        r.order = orig;
        raise(ERR_R_ASN1_LIB, F);
        return false;
    }
    // SAFETY: a live group.
    let cofactor = unsafe { EC_GROUP_get0_cofactor(group) };
    if !cofactor.is_null() {
        let orig = r.cofactor;
        // SAFETY: as above.
        r.cofactor = unsafe { BN_to_ASN1_INTEGER(cofactor, orig) };
        if r.cofactor.is_null() {
            r.cofactor = orig;
            raise(ERR_R_ASN1_LIB, F);
            return false;
        }
    }
    true
}

ffi_export! {
    /// The group's explicit parameters, into `params` if given (else a new `ECPARAMETERS`), or
    /// NULL.
    ///
    /// # Safety
    /// `group` is a live group; `params` is NULL or a live `ECPARAMETERS`.
    pub unsafe extern "C" fn EC_GROUP_get_ecparameters(group: *const EC_GROUP, params: *mut ECPARAMETERS) -> *mut ECPARAMETERS
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        let ret = if params.is_null() {
            // SAFETY: no preconditions.
            let r = unsafe { ECPARAMETERS_new() };
            if r.is_null() {
                raise(ERR_R_ASN1_LIB, "EC_GROUP_get_ecparameters");
                return ptr::null_mut();
            }
            r
        } else {
            params
        };
        // SAFETY: the caller's group; a live structure.
        if unsafe { fill_ecparameters(group, ret.cast()) } {
            return ret;
        }
        if params.is_null() {
            // SAFETY: the structure made above.
            unsafe { ECPARAMETERS_free(ret) };
        }
        ptr::null_mut()
    }
}

/// Frees an `ECPKPARAMETERS`' value as its type, leaving none.
///
/// # Safety
/// `p` is a live `ECPKPARAMETERS`.
unsafe fn clear_pk(p: &mut PkParams) {
    let v = core::mem::replace(&mut p.value, ptr::null_mut());
    if v.is_null() {
        return;
    }
    match p.kind {
        // SAFETY: a named curve's object.
        TYPE_NAMED => unsafe { ASN1_OBJECT_free(v.cast()) },
        // SAFETY: explicit parameters.
        TYPE_EXPLICIT => unsafe { ECPARAMETERS_free(v.cast()) },
        TYPE_IMPLICIT => {
            // SAFETY: no preconditions.
            let it = unsafe { ASN1_NULL_it() };
            // SAFETY: implicitlyCA's NULL, of that item.
            unsafe { ASN1_item_free(v.cast(), it) };
        }
        _ => {}
    }
}

ffi_export! {
    /// The group's ECPKParameters (its curve's object with the named-curve flag, else its
    /// explicit parameters), into `params` if given, or NULL.
    ///
    /// # Safety
    /// `group` is a live group; `params` is NULL or a live `ECPKPARAMETERS`.
    pub unsafe extern "C" fn EC_GROUP_get_ecpkparameters(group: *const EC_GROUP, params: *mut ECPKPARAMETERS) -> *mut ECPKPARAMETERS
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        const F: &str = "EC_GROUP_get_ecpkparameters";
        let ret: *mut PkParams = if params.is_null() {
            // SAFETY: no preconditions.
            let r = unsafe { ECPKPARAMETERS_new() };
            if r.is_null() {
                raise(ERR_R_ASN1_LIB, F);
                return ptr::null_mut();
            }
            r.cast()
        } else {
            params.cast()
        };
        // SAFETY: a live structure.
        let r = unsafe { &mut *ret };
        // SAFETY: as above.
        unsafe { clear_pk(r) };
        let mut ok = true;
        // SAFETY: the caller's group.
        if unsafe { EC_GROUP_get_asn1_flag(group) } == OPENSSL_EC_NAMED_CURVE {
            // SAFETY: as above.
            let nid = unsafe { EC_GROUP_get_curve_name(group) };
            if nid == 0 {
                ok = false;
            } else {
                // SAFETY: no preconditions.
                let obj = unsafe { OBJ_nid2obj(nid) };
                // SAFETY: NULL or a live object.
                if obj.is_null() || unsafe { OBJ_length(obj) } == 0 {
                    // SAFETY: as above, freed once.
                    unsafe { ASN1_OBJECT_free(obj) };
                    raise(EC_R_MISSING_OID, F);
                    ok = false;
                } else {
                    r.kind = TYPE_NAMED;
                    r.value = obj.cast();
                }
            }
        } else {
            r.kind = TYPE_EXPLICIT;
            // SAFETY: the caller's group.
            r.value = unsafe { EC_GROUP_get_ecparameters(group, ptr::null_mut()) }.cast();
            ok = !r.value.is_null();
        }
        if ok {
            return ret.cast();
        }
        if params.is_null() {
            // SAFETY: the structure made above.
            unsafe { ECPKPARAMETERS_free(ret.cast()) };
        }
        ptr::null_mut()
    }
}

/// A `BIGNUM` of an OCTET STRING's octets, or NULL.
///
/// # Safety
/// `s` is a live string.
unsafe fn octets_bn(s: *const ASN1_OCTET_STRING) -> *mut BIGNUM {
    // SAFETY: the caller's guarantee.
    let st = unsafe { &*s };
    // SAFETY: the string's own octets.
    unsafe { BN_bin2bn(st.data, st.length, ptr::null_mut()) }
}

/// The binary field's polynomial from its characteristic-two parameters, with the field size,
/// or `None` with the error raised.
///
/// # Safety
/// `c` is a live `X9_62_CHARACTERISTIC_TWO`; `p` a live number.
unsafe fn char_two_polynomial(c: &CharTwo, p: *mut BIGNUM) -> bool {
    const F: &str = "EC_GROUP_new_from_ecparameters";
    // SAFETY: NULL or a live object.
    let nid = unsafe { OBJ_obj2nid(c.kind) };
    let bits: Vec<c_int> = if nid == NID_X9_62_tpBasis {
        if c.p.is_null() {
            raise(EC_R_ASN1_ERROR, F);
            return false;
        }
        // SAFETY: the trinomial's INTEGER.
        let k = unsafe { ASN1_INTEGER_get(c.p.cast()) };
        if !(c_long::from(c.m) > k && k > 0) {
            raise(EC_R_INVALID_TRINOMIAL_BASIS, F);
            return false;
        }
        // Below `m`, a 32-bit number.
        vec![c.m, c_int::try_from(k).unwrap_or(0), 0]
    } else if nid == NID_X9_62_ppBasis {
        let pp: *const Pentanomial = c.p.cast();
        if pp.is_null() {
            raise(EC_R_ASN1_ERROR, F);
            return false;
        }
        // SAFETY: the pentanomial's terms.
        let t = unsafe { &*pp };
        if !(c.m > t.k3 && t.k3 > t.k2 && t.k2 > t.k1 && t.k1 > 0) {
            raise(EC_R_INVALID_PENTANOMIAL_BASIS, F);
            return false;
        }
        vec![c.m, t.k1, t.k2, t.k3, 0]
    } else if nid == NID_X9_62_onBasis {
        raise(EC_R_NOT_IMPLEMENTED, F);
        return false;
    } else {
        raise(EC_R_ASN1_ERROR, F);
        return false;
    };
    // SAFETY: a live number; each bit below `OPENSSL_ECC_MAX_FIELD_BITS`.
    bits.into_iter().all(|b| unsafe { BN_set_bit(p, b) } != 0)
}

/// `EC_GROUP_new_from_ecparameters`' work; frees nothing of `params`.
///
/// # Safety
/// `params` is a live `ECPARAMETERS`.
unsafe fn from_ecparameters(params: &Params) -> *mut EC_GROUP {
    const F: &str = "EC_GROUP_new_from_ecparameters";
    // SAFETY: NULL or the structure's live field.
    let field = unsafe { params.field_id.as_ref() };
    let Some(field) = field.filter(|f| !f.field_type.is_null() && !f.p.is_null()) else {
        raise(EC_R_ASN1_ERROR, F);
        return ptr::null_mut();
    };
    // SAFETY: as above.
    let curve = unsafe { params.curve.as_ref() };
    // SAFETY: NULL or live strings.
    let has_data = |s: *mut ASN1_OCTET_STRING| !s.is_null() && !unsafe { (*s).data }.is_null();
    let Some(curve) = curve.filter(|c| has_data(c.a) && has_data(c.b)) else {
        raise(EC_R_ASN1_ERROR, F);
        return ptr::null_mut();
    };
    let mut ret: *mut EC_GROUP = ptr::null_mut();
    let (mut p, mut a, mut b): (*mut BIGNUM, *mut BIGNUM, *mut BIGNUM) =
        (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    let mut point: *mut EC_POINT = ptr::null_mut();
    let mut dup: *mut EC_GROUP = ptr::null_mut();
    let ok = (|| -> bool {
        // SAFETY: live strings.
        a = unsafe { octets_bn(curve.a) };
        if a.is_null() {
            raise(ERR_R_BN_LIB, F);
            return false;
        }
        // SAFETY: as above.
        b = unsafe { octets_bn(curve.b) };
        if b.is_null() {
            raise(ERR_R_BN_LIB, F);
            return false;
        }
        // SAFETY: a live object.
        let ft = unsafe { OBJ_obj2nid(field.field_type) };
        let field_bits: c_long;
        if ft == NID_X9_62_characteristic_two_field {
            // SAFETY: the binary field's parameters.
            let c = unsafe { &*field.p.cast::<CharTwo>() };
            field_bits = c_long::from(c.m);
            if field_bits > c_long::from(OPENSSL_ECC_MAX_FIELD_BITS) {
                raise(EC_R_FIELD_TOO_LARGE, F);
                return false;
            }
            // SAFETY: no preconditions.
            p = unsafe { BN_new() };
            if p.is_null() {
                raise(ERR_R_BN_LIB, F);
                return false;
            }
            // SAFETY: as above.
            if !unsafe { char_two_polynomial(c, p) } {
                return false;
            }
            // SAFETY: live numbers.
            ret = unsafe { EC_GROUP_new_curve_GF2m(p, a, b, ptr::null_mut()) };
        } else if ft == NID_X9_62_prime_field {
            // SAFETY: the prime field's INTEGER.
            p = unsafe { ASN1_INTEGER_to_BN(field.p.cast(), ptr::null_mut()) };
            if p.is_null() {
                raise(ERR_R_ASN1_LIB, F);
                return false;
            }
            // SAFETY: a live number.
            if unsafe { BN_is_negative(p) } != 0 || unsafe { BN_is_zero(p) } != 0 {
                raise(EC_R_INVALID_FIELD, F);
                return false;
            }
            // SAFETY: as above.
            field_bits = c_long::from(unsafe { BN_num_bits(p) });
            if field_bits > c_long::from(OPENSSL_ECC_MAX_FIELD_BITS) {
                raise(EC_R_FIELD_TOO_LARGE, F);
                return false;
            }
            // SAFETY: live numbers.
            ret = unsafe { EC_GROUP_new_curve_GFp(p, a, b, ptr::null_mut()) };
        } else {
            raise(EC_R_INVALID_FIELD, F);
            return false;
        }
        if ret.is_null() {
            raise(ERR_R_EC_LIB, F);
            return false;
        }
        if !curve.seed.is_null() {
            // SAFETY: a live string.
            let seed = unsafe { &*curve.seed };
            let Ok(len) = usize::try_from(seed.length) else {
                raise(EC_R_ASN1_ERROR, F);
                return false;
            };
            if len == 0 {
                raise(EC_R_ASN1_ERROR, F);
                return false;
            }
            // SAFETY: the group; the string's own octets.
            if unsafe { EC_GROUP_set_seed(ret, seed.data, len) } == 0 {
                return false;
            }
        }
        // SAFETY: NULL or a live string.
        let base = unsafe { params.base.as_ref() };
        let Some(base) = base.filter(|s| !s.data.is_null() && s.length != 0) else {
            raise(EC_R_ASN1_ERROR, F);
            return false;
        };
        if params.order.is_null() {
            raise(EC_R_ASN1_ERROR, F);
            return false;
        }
        // SAFETY: the group.
        point = unsafe { EC_POINT_new(ret) };
        if point.is_null() {
            return false;
        }
        // SAFETY: the string's first octet.
        let first = unsafe { *base.data };
        let form: point_conversion_form_t = (first & !1).into();
        // SAFETY: the group.
        unsafe { EC_GROUP_set_point_conversion_form(ret, form) };
        let len = usize::try_from(base.length).unwrap_or(0);
        // SAFETY: the group and its point; the string's octets.
        if unsafe { EC_POINT_oct2point(ret, point, base.data, len, ptr::null_mut()) } == 0 {
            raise(ERR_R_EC_LIB, F);
            return false;
        }
        // SAFETY: a live INTEGER; `a`, reused for the order.
        if unsafe { ASN1_INTEGER_to_BN(params.order, a) }.is_null() {
            raise(ERR_R_ASN1_LIB, F);
            return false;
        }
        // SAFETY: a live number.
        if unsafe { BN_is_negative(a) } != 0 || unsafe { BN_is_zero(a) } != 0 {
            raise(EC_R_INVALID_GROUP_ORDER, F);
            return false;
        }
        // The Hasse bound.
        // SAFETY: as above.
        if c_long::from(unsafe { BN_num_bits(a) }) > field_bits.saturating_add(1) {
            raise(EC_R_INVALID_GROUP_ORDER, F);
            return false;
        }
        if params.cofactor.is_null() {
            // SAFETY: the number made above, freed once.
            unsafe { BN_free(b) };
            b = ptr::null_mut();
        // SAFETY: a live INTEGER; `b`, reused for the cofactor.
        } else if unsafe { ASN1_INTEGER_to_BN(params.cofactor, b) }.is_null() {
            raise(ERR_R_ASN1_LIB, F);
            return false;
        }
        // SAFETY: the group, its point, and live numbers (or NULL).
        if unsafe { EC_GROUP_set_generator(ret, point, a, b) } == 0 {
            raise(ERR_R_EC_LIB, F);
            return false;
        }
        // A built-in curve's parameters give its named group (without the seed and cofactor,
        // which can't make the group another one).
        // SAFETY: the group.
        dup = unsafe { EC_GROUP_dup(ret) };
        let copied = !dup.is_null()
            // SAFETY: the copy.
            && unsafe { EC_GROUP_set_seed(dup, ptr::null(), 0) } == 1
            // SAFETY: the copy, the point, and the order.
            && unsafe { EC_GROUP_set_generator(dup, point, a, ptr::null()) } != 0;
        if !copied {
            raise(ERR_R_EC_LIB, F);
            return false;
        }
        // SAFETY: the copy.
        let mut name = unsafe { curve_nid_from_params(dup, ptr::null()) };
        if name != NID_undef {
            // wtls12 and secp224r1 are one curve; the latter has the specialized method.
            if name == NID_wap_wsg_idm_ecid_wtls12
                && curves::by_nid(NID_secp224r1).is_some_and(|c| c.method == Method::Nistp224)
            {
                name = NID_secp224r1;
            }
            // SAFETY: no preconditions.
            let named = unsafe { EC_GROUP_new_by_curve_name(name) };
            if named.is_null() {
                raise(ERR_R_EC_LIB, F);
                return false;
            }
            // SAFETY: the group made above, replaced.
            unsafe { EC_GROUP_free(ret) };
            ret = named;
            // SAFETY: the named group.
            unsafe { EC_GROUP_set_asn1_flag(ret, OPENSSL_EC_EXPLICIT_CURVE) };
            // SAFETY: as above.
            if curve.seed.is_null() && unsafe { EC_GROUP_set_seed(ret, ptr::null(), 0) } != 1 {
                return false;
            }
        }
        true
    })();
    if !ok {
        // SAFETY: NULL or the group made above.
        unsafe { EC_GROUP_free(ret) };
        ret = ptr::null_mut();
    }
    // SAFETY: NULL or the copy.
    unsafe { EC_GROUP_free(dup) };
    for n in [p, a, b] {
        // SAFETY: NULL or numbers made above, each freed once.
        unsafe { BN_free(n) };
    }
    // SAFETY: NULL or the point made above.
    unsafe { EC_POINT_free(point) };
    ret
}

ffi_export! {
    /// The group explicit parameters describe (the named group when they're a built-in
    /// curve's, with the explicit flag), or NULL.
    ///
    /// # Safety
    /// `params` is NULL or a live `ECPARAMETERS`.
    pub unsafe extern "C" fn EC_GROUP_new_from_ecparameters(params: *const ECPARAMETERS) -> *mut EC_GROUP
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { params.cast::<Params>().as_ref() }) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, "EC_GROUP_new_from_ecparameters");
            return ptr::null_mut();
        };
        // SAFETY: as above.
        unsafe { from_ecparameters(p) }
    }
}

ffi_export! {
    /// The group ECPKParameters describe, with the flag of their kind, or NULL (without an
    /// error for implicitlyCA).
    ///
    /// # Safety
    /// `params` is NULL or a live `ECPKPARAMETERS`.
    pub unsafe extern "C" fn EC_GROUP_new_from_ecpkparameters(params: *const ECPKPARAMETERS) -> *mut EC_GROUP
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        const F: &str = "EC_GROUP_new_from_ecpkparameters";
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { params.cast::<PkParams>().as_ref() }) else {
            raise(EC_R_MISSING_PARAMETERS, F);
            return ptr::null_mut();
        };
        match p.kind {
            TYPE_NAMED => {
                // SAFETY: NULL or the named curve's object.
                let nid = unsafe { OBJ_obj2nid(p.value.cast()) };
                // SAFETY: no preconditions.
                let ret = unsafe { EC_GROUP_new_by_curve_name(nid) };
                if ret.is_null() {
                    raise(EC_R_EC_GROUP_NEW_BY_NAME_FAILURE, F);
                    return ptr::null_mut();
                }
                // SAFETY: the group made above.
                unsafe { EC_GROUP_set_asn1_flag(ret, OPENSSL_EC_NAMED_CURVE) };
                ret
            }
            TYPE_EXPLICIT => {
                // SAFETY: NULL or the explicit parameters.
                let ret = unsafe { EC_GROUP_new_from_ecparameters(p.value.cast()) };
                if ret.is_null() {
                    raise(ERR_R_EC_LIB, F);
                    return ptr::null_mut();
                }
                // SAFETY: the group made above.
                unsafe { EC_GROUP_set_asn1_flag(ret, OPENSSL_EC_EXPLICIT_CURVE) };
                ret
            }
            TYPE_IMPLICIT => ptr::null_mut(),
            _ => {
                raise(EC_R_ASN1_ERROR, F);
                ptr::null_mut()
            }
        }
    }
}

ffi_export! {
    /// Decodes ECPKParameters into a group (marked as decoded from explicit parameters when
    /// they were), replacing `*a` if given; advances `*in` past them.
    ///
    /// # Safety
    /// `a` is NULL or holds NULL or a live group; `in` holds `len` readable octets.
    pub unsafe extern "C" fn d2i_ECPKParameters(a: *mut *mut EC_GROUP, r#in: *mut *const c_uchar, len: c_long) -> *mut EC_GROUP
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        if r#in.is_null() {
            raise(ERR_R_PASSED_NULL_PARAMETER, "d2i_ECPKParameters");
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let mut p = unsafe { *r#in };
        // SAFETY: no preconditions.
        let it = unsafe { ECPKPARAMETERS_it() };
        // SAFETY: as above; the type's item.
        let params: *mut PkParams = unsafe {
            ASN1_item_d2i(ptr::null_mut(), &raw mut p, len, it)
        }
        .cast();
        if params.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the structure just decoded.
        let group = unsafe { EC_GROUP_new_from_ecpkparameters(params.cast()) };
        if !group.is_null() {
            // SAFETY: as above.
            if unsafe { (*params).kind } == TYPE_EXPLICIT {
                // SAFETY: the group made above.
                unsafe { set_decoded_from_explicit(group, true) };
            }
            if !a.is_null() {
                // SAFETY: the caller's pointer.
                let old = unsafe { *a };
                // SAFETY: NULL or the caller's group, replaced.
                unsafe { EC_GROUP_free(old) };
                // SAFETY: as above.
                unsafe { *a = group };
            }
            // SAFETY: as above.
            unsafe { *r#in = p };
        }
        // SAFETY: the structure decoded above.
        unsafe { ECPKPARAMETERS_free(params.cast()) };
        group
    }
}

ffi_export! {
    /// Encodes the group's ECPKParameters (`i2d` conventions); 0 on failure.
    ///
    /// # Safety
    /// `a` is a live group; `out` is NULL or holds NULL or room for the encoding.
    pub unsafe extern "C" fn i2d_ECPKParameters(a: *const EC_GROUP, out: *mut *mut c_uchar) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's group.
        let tmp = unsafe { EC_GROUP_get_ecpkparameters(a, ptr::null_mut()) };
        if tmp.is_null() {
            raise(EC_R_GROUP2PKPARAMETERS_FAILURE, "i2d_ECPKParameters");
            return 0;
        }
        // SAFETY: no preconditions.
        let it = unsafe { ECPKPARAMETERS_it() };
        // SAFETY: the structure made above; the caller's buffer.
        let ret = unsafe { ASN1_item_i2d(tmp.cast(), out, it) };
        // SAFETY: as above.
        unsafe { ECPKPARAMETERS_free(tmp) };
        if ret == 0 {
            raise(EC_R_I2D_ECPKPARAMETERS_FAILURE, "i2d_ECPKParameters");
            return 0;
        }
        ret
    }
}

/// Writes formatted text, as a success (`BIO_printf(...) > 0`).
macro_rules! printf {
    ($bp:expr, $fmt:expr $(, $arg:expr)*) => {
        // SAFETY: a live BIO; a format with matching arguments.
        (unsafe { BIO_printf($bp, $fmt.as_ptr() $(, $arg)*) }) > 0
    };
}

/// `print_bin`: a label, then the octets in lines of fifteen, each line indented by `off` + 4.
///
/// # Safety
/// `bp` is a live BIO.
unsafe fn print_bin(bp: *mut BIO, name: &CStr, buf: &[u8], off: c_int) -> bool {
    let off = usize::try_from(off.min(128)).unwrap_or(0);
    let spaces = [b' '; 128 + 5];
    let write = |s: &[u8]| {
        let n = c_int::try_from(s.len()).unwrap_or(0);
        // SAFETY: a live BIO; a slice.
        n == 0 || unsafe { BIO_write(bp, s.as_ptr().cast(), n) } > 0
    };
    if !write(spaces.get(..off).unwrap_or_default()) || !printf!(bp, c"%s", name.as_ptr()) {
        return false;
    }
    let mut line = vec![b'\n'];
    line.extend_from_slice(spaces.get(..off.saturating_add(4)).unwrap_or_default());
    for (i, byte) in buf.iter().enumerate() {
        if i % 15 == 0 && !write(&line) {
            return false;
        }
        let sep = if i.saturating_add(1) == buf.len() {
            c""
        } else {
            c":"
        };
        if !printf!(bp, c"%02x%s", c_int::from(*byte), sep.as_ptr()) {
            return false;
        }
    }
    write(b"\n")
}

/// `ECPKParameters_print`'s output; `Err` carries the reason to raise.
///
/// # Safety
/// `bp` is a live BIO; `x` is a live group.
unsafe fn print_params(bp: *mut BIO, x: *const EC_GROUP, off: c_int) -> Result<(), c_int> {
    let bio = Err(ERR_R_BIO_LIB);
    // SAFETY: the caller's guarantee, here and below.
    let indent = || unsafe { BIO_indent(bp, off, 128) } != 0;
    // SAFETY: as above.
    let number = |label: &CStr, n: *const BIGNUM| unsafe {
        ASN1_bn_print(bp, label.as_ptr(), n, ptr::null_mut(), off)
    } != 0;
    // SAFETY: as above.
    if unsafe { EC_GROUP_get_asn1_flag(x) } != 0 {
        if !indent() {
            return bio;
        }
        // SAFETY: as above.
        let nid = unsafe { EC_GROUP_get_curve_name(x) };
        if nid == 0 {
            return bio;
        }
        // SAFETY: no preconditions.
        let sn = unsafe { OBJ_nid2sn(nid) };
        if !printf!(bp, c"ASN1 OID: %s", sn) || !printf!(bp, c"\n") {
            return bio;
        }
        // SAFETY: no preconditions.
        let nist = unsafe { EC_curve_nid2nist(nid) };
        if !nist.is_null() && (!indent() || !printf!(bp, c"NIST CURVE: %s\n", nist)) {
            return bio;
        }
        return Ok(());
    }
    // SAFETY: as above.
    let field_type = unsafe { EC_GROUP_get_field_type(x) };
    let char_two = field_type == NID_X9_62_characteristic_two_field;
    let nums = Numbers::new().ok_or(ERR_R_BN_LIB)?;
    // SAFETY: as above; live numbers.
    if unsafe { EC_GROUP_get_curve(x, nums.0[0], nums.0[1], nums.0[2], ptr::null_mut()) } == 0 {
        return Err(ERR_R_EC_LIB);
    }
    // SAFETY: as above.
    let point = unsafe { EC_GROUP_get0_generator(x) };
    if point.is_null() {
        return Err(ERR_R_EC_LIB);
    }
    // SAFETY: as above.
    let order = unsafe { EC_GROUP_get0_order(x) };
    // SAFETY: as above.
    let cofactor = unsafe { EC_GROUP_get0_cofactor(x) };
    if order.is_null() {
        return Err(ERR_R_EC_LIB);
    }
    // SAFETY: as above.
    let form = unsafe { EC_GROUP_get_point_conversion_form(x) };
    // SAFETY: the group and its generator.
    let generator = unsafe { Encoded::of(x, point, form) }.ok_or(ERR_R_EC_LIB)?;
    // SAFETY: as above.
    let seed = unsafe { EC_GROUP_get0_seed(x) };
    let seed_bytes: &[u8] = if seed.is_null() {
        &[]
    } else {
        // SAFETY: the caller's group.
        let n = unsafe { EC_GROUP_get_seed_len(x) };
        // SAFETY: the group's seed of its length.
        unsafe { core::slice::from_raw_parts(seed, n) }
    };
    // SAFETY: no preconditions.
    let sn = unsafe { OBJ_nid2sn(field_type) };
    if !indent() || !printf!(bp, c"Field Type: %s\n", sn) {
        return bio;
    }
    if char_two {
        // SAFETY: as above.
        let basis = unsafe { EC_GROUP_get_basis_type(x) };
        if basis == 0 || !indent() {
            return bio;
        }
        // SAFETY: no preconditions.
        let bsn = unsafe { OBJ_nid2sn(basis) };
        if !printf!(bp, c"Basis Type: %s\n", bsn) || !number(c"Polynomial:", nums.0[0]) {
            return bio;
        }
    } else if !number(c"Prime:", nums.0[0]) {
        return bio;
    }
    if !number(c"A:   ", nums.0[1]) || !number(c"B:   ", nums.0[2]) {
        return bio;
    }
    let label = if form == POINT_CONVERSION_COMPRESSED {
        c"Generator (compressed):"
    } else if form == POINT_CONVERSION_UNCOMPRESSED {
        c"Generator (uncompressed):"
    } else {
        c"Generator (hybrid):"
    };
    // SAFETY: as above.
    if !unsafe { print_bin(bp, label, generator.bytes(), off) } || !number(c"Order: ", order) {
        return bio;
    }
    if !cofactor.is_null() && !number(c"Cofactor: ", cofactor) {
        return bio;
    }
    // SAFETY: as above.
    if !seed.is_null() && !unsafe { print_bin(bp, c"Seed:", seed_bytes, off) } {
        return bio;
    }
    Ok(())
}

/// Three numbers freed on drop.
struct Numbers([*mut BIGNUM; 3]);

impl Numbers {
    fn new() -> Option<Self> {
        // SAFETY: no preconditions.
        let n = Self([unsafe { BN_new() }, unsafe { BN_new() }, unsafe {
            BN_new()
        }]);
        n.0.iter().all(|b| !b.is_null()).then_some(n)
    }
}

impl Drop for Numbers {
    fn drop(&mut self) {
        for b in self.0 {
            // SAFETY: numbers made by `new`, or NULL, each freed once.
            unsafe { BN_free(b) };
        }
    }
}

/// A point's encoding from `EC_POINT_point2buf`, cleared and freed on drop.
pub(crate) struct Encoded(*mut c_uchar, usize);

impl Encoded {
    /// The encoding of `p` in `form`, or `None`.
    ///
    /// # Safety
    /// `g` is a live group and `p` a live point.
    pub(crate) unsafe fn of(
        g: *const EC_GROUP,
        p: *const EC_POINT,
        form: point_conversion_form_t,
    ) -> Option<Self> {
        let mut buf: *mut c_uchar = ptr::null_mut();
        // SAFETY: a live group and point; a local.
        let len = unsafe { EC_POINT_point2buf(g, p, form, &raw mut buf, ptr::null_mut()) };
        (len != 0).then_some(Self(buf, len))
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        // SAFETY: the encoding's octets.
        unsafe { core::slice::from_raw_parts(self.0, self.1) }
    }
}

impl Drop for Encoded {
    fn drop(&mut self) {
        // SAFETY: the encoding, freed once.
        unsafe { mem::release_clean(self.0.cast(), self.1) };
    }
}

ffi_export! {
    /// Prints the group's parameters (its curve's names for the named-curve flag), each line
    /// indented by `off`. 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `x` is NULL or a live group.
    pub unsafe extern "C" fn ECPKParameters_print(bp: *mut BIO, x: *const EC_GROUP, off: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let r = if x.is_null() {
            Err(ERR_R_PASSED_NULL_PARAMETER)
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { print_params(bp, x, off) }
        };
        match r {
            Ok(()) => 1,
            Err(reason) => {
                raise(reason, "ECPKParameters_print");
                0
            }
        }
    }
}

ffi_export! {
    /// `ECPKParameters_print` to a `FILE`.
    ///
    /// # Safety
    /// `fp` is a live `FILE`; `x` is NULL or a live group.
    pub unsafe extern "C" fn ECPKParameters_print_fp(fp: *mut FILE, x: *const EC_GROUP, off: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let b = unsafe { crate::bio::file::BIO_new_fp(fp, BIO_NOCLOSE) };
        if b.is_null() {
            raise(ERR_R_BUF_LIB, "ECPKParameters_print_fp");
            return 0;
        }
        // SAFETY: the BIO; the caller's group.
        let ret = unsafe { ECPKParameters_print(b, x, off) };
        // SAFETY: the BIO made above.
        unsafe { BIO_free(b) };
        ret
    }
}

#[cfg(test)]
mod tests {
    use rustyssl_abi::{NID_ipsec3, NID_sect163k1};

    use super::*;

    /// docs/DEVIATIONS.md: OpenSSL's dereferences the NULL structure.
    #[test]
    fn null_ecparameters_fail() {
        // SAFETY: NULL.
        assert!(unsafe { EC_GROUP_new_from_ecparameters(ptr::null()) }.is_null());
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }

    /// docs/DEVIATIONS.md: OpenSSL's frees a binary field's parameters as an ANY.
    #[test]
    fn existing_ecparameters_are_refilled() {
        // SAFETY: no preconditions.
        let g = unsafe { EC_GROUP_new_by_curve_name(NID_sect163k1) };
        // SAFETY: a live group.
        let ep = unsafe { EC_GROUP_get_ecparameters(g, ptr::null_mut()) };
        assert!(!ep.is_null());
        for _ in 0..3 {
            // SAFETY: the group; its parameters.
            assert_eq!(unsafe { EC_GROUP_get_ecparameters(g, ep) }, ep);
        }
        // SAFETY: freed once.
        unsafe { ECPARAMETERS_free(ep) };
        // SAFETY: as above.
        unsafe { EC_GROUP_free(g) };
    }

    /// docs/DEVIATIONS.md: OpenSSL's frees the caller's structure when it fails.
    #[test]
    fn a_failed_ecpkparameters_leaves_the_callers() {
        // SAFETY: no preconditions.
        let g = unsafe { EC_GROUP_new_by_curve_name(NID_ipsec3) };
        // SAFETY: a live group.
        unsafe { EC_GROUP_set_asn1_flag(g, OPENSSL_EC_NAMED_CURVE) };
        // SAFETY: no preconditions.
        let pk = unsafe { ECPKPARAMETERS_new() };
        // SAFETY: the group; a live structure. (A curve without an OID has no named form.)
        assert!(unsafe { EC_GROUP_get_ecpkparameters(g, pk) }.is_null());
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
        // SAFETY: still the caller's, freed once.
        unsafe { ECPKPARAMETERS_free(pk) };
        // SAFETY: as above.
        unsafe { EC_GROUP_free(g) };
    }

    /// The structures' layouts are OpenSSL's private ones, which applications can't see, but
    /// the templates must agree with them.
    #[test]
    fn layouts() {
        assert_eq!(size_of::<Params>(), 48);
        assert_eq!(size_of::<PkParams>(), 16);
        assert_eq!(offset_of!(CharTwo, p), 16);
    }
}
