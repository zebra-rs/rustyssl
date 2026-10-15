//! Elliptic curves' C API (`EC_GROUP_new(3)`, `EC_POINT_new(3)`, `EC_POINT_add(3)`,
//! `EC_GFp_simple_method(3)`): groups, points, and methods over `rustyssl_crypto::ec`, which
//! computes as OpenSSL does (see its documentation).
//!
//! - An `EC_METHOD` is one of a fixed set of handles, one per method of the default build.
//! - An `EC_GROUP` holds the core group, and the objects its `get0` functions hand out (the
//!   field, order, and cofactor as `BIGNUM`s, the generator as an `EC_POINT`, the seed), each
//!   at a stable address for the group's life and kept equal to the group's own values.
//! - An `EC_POINT` holds its coordinates and, as OpenSSL's, the method and curve name of the
//!   group it was made for, which decide what it can be used with (`ec_point_is_compat`).
//!
//! The random numbers the operations draw come from the private generator of the `BN_CTX`'s
//! library context, or the group's when there's no `BN_CTX`, as in OpenSSL.

pub(crate) mod asn1;
pub(crate) mod curves;
pub(crate) mod group;
pub(crate) mod params;
pub(crate) mod point;

use core::ffi::c_int;
use std::sync::LazyLock;

use rustyssl_abi::{
    BN_CTX, EC_METHOD, EC_R_BUFFER_TOO_SMALL, EC_R_CANNOT_INVERT, EC_R_DISCRIMINANT_IS_ZERO,
    EC_R_INCOMPATIBLE_OBJECTS, EC_R_INVALID_COMPRESSED_POINT, EC_R_INVALID_COMPRESSION_BIT,
    EC_R_INVALID_ENCODING, EC_R_INVALID_FIELD, EC_R_INVALID_FORM, EC_R_INVALID_GROUP_ORDER,
    EC_R_LADDER_POST_FAILURE, EC_R_LADDER_PRE_FAILURE, EC_R_LADDER_STEP_FAILURE,
    EC_R_NOT_A_NIST_PRIME, EC_R_POINT_AT_INFINITY, EC_R_POINT_IS_NOT_ON_CURVE,
    EC_R_UNDEFINED_GENERATOR, EC_R_UNKNOWN_COFACTOR, EC_R_UNKNOWN_ORDER, EC_R_UNSUPPORTED_FIELD,
    EC_R_WRONG_CURVE_PARAMETERS, ERR_LIB_EC, ERR_R_BN_LIB, ERR_R_EC_LIB, ERR_R_INTERNAL_ERROR,
    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, NID_X9_62_characteristic_two_field, NID_X9_62_prime_field,
    OSSL_LIB_CTX,
};
use rustyssl_crypto::ec::curves::Field;
use rustyssl_crypto::ec::{Error, Meth, Reason};

use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::provider::Ptr;

/// What an `EC_METHOD` handle points to.
pub(crate) struct Method(pub(crate) Meth);

handle_type!(EC_METHOD => Method);

/// Every method, in a fixed order.
const METHS: [Meth; 10] = [
    Meth::Simple,
    Meth::Mont,
    Meth::Nist,
    Meth::Nistp224,
    Meth::Nistp256,
    Meth::Nistp384,
    Meth::Nistp521,
    Meth::Nistz256,
    Meth::Sm2p256,
    Meth::Gf2m,
];

/// The method handles, made once and never freed.
static METHODS: LazyLock<Vec<Ptr<EC_METHOD>>> = LazyLock::new(|| {
    METHS
        .iter()
        .map(|m| Ptr(EC_METHOD::new_handle(Method(*m))))
        .collect()
});

/// The handle of a method.
pub(crate) fn method_ptr(m: Meth) -> *const EC_METHOD {
    METHS
        .iter()
        .position(|x| *x == m)
        .and_then(|i| METHODS.get(i))
        .map_or(core::ptr::null(), |p| p.0.cast_const())
}

/// The method behind a handle.
///
/// # Safety
/// `m` is NULL or a method handle.
pub(crate) unsafe fn method_of(m: *const EC_METHOD) -> Option<Meth> {
    // SAFETY: the caller's guarantee.
    unsafe { EC_METHOD::get(m) }.map(|x| x.0)
}

/// A method's field type (`NID_X9_62_prime_field` or `NID_X9_62_characteristic_two_field`).
pub(crate) fn field_type(m: Meth) -> c_int {
    match m.field() {
        Field::Prime => NID_X9_62_prime_field,
        Field::Binary => NID_X9_62_characteristic_two_field,
    }
}

/// Raises a core error's entries, in order.
pub(crate) fn raise(e: &Error) {
    for r in &e.0 {
        let code = match r.reason {
            Reason::InvalidField => EC_R_INVALID_FIELD,
            Reason::NotANistPrime => EC_R_NOT_A_NIST_PRIME,
            Reason::WrongCurveParameters => EC_R_WRONG_CURVE_PARAMETERS,
            Reason::UnsupportedField => EC_R_UNSUPPORTED_FIELD,
            Reason::CannotInvert => EC_R_CANNOT_INVERT,
            Reason::PointAtInfinity => EC_R_POINT_AT_INFINITY,
            Reason::PointIsNotOnCurve => EC_R_POINT_IS_NOT_ON_CURVE,
            Reason::UnknownOrder => EC_R_UNKNOWN_ORDER,
            Reason::UnknownCofactor => EC_R_UNKNOWN_COFACTOR,
            Reason::InvalidGroupOrder => EC_R_INVALID_GROUP_ORDER,
            Reason::LadderPreFailure => EC_R_LADDER_PRE_FAILURE,
            Reason::LadderStepFailure => EC_R_LADDER_STEP_FAILURE,
            Reason::LadderPostFailure => EC_R_LADDER_POST_FAILURE,
            Reason::InvalidCompressedPoint => EC_R_INVALID_COMPRESSED_POINT,
            Reason::InvalidCompressionBit => EC_R_INVALID_COMPRESSION_BIT,
            Reason::InvalidEncoding => EC_R_INVALID_ENCODING,
            Reason::InvalidForm => EC_R_INVALID_FORM,
            Reason::BufferTooSmall => EC_R_BUFFER_TOO_SMALL,
            Reason::IncompatibleObjects => EC_R_INCOMPATIBLE_OBJECTS,
            Reason::UndefinedGenerator => EC_R_UNDEFINED_GENERATOR,
            Reason::DiscriminantIsZero => EC_R_DISCRIMINANT_IS_ZERO,
            Reason::CoordinatesOutOfRange => rustyssl_abi::EC_R_COORDINATES_OUT_OF_RANGE,
            Reason::ShouldNotHaveBeenCalled => ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
            Reason::BnLib => ERR_R_BN_LIB,
            Reason::EcLib => ERR_R_EC_LIB,
            Reason::InternalError => ERR_R_INTERNAL_ERROR,
            Reason::Bn(b) => {
                crate::bn::raise(b);
                continue;
            }
        };
        err::raise(ERR_LIB_EC, code, r.func);
    }
}

/// The private generator for an operation: the `BN_CTX`'s library context's, else `libctx`.
///
/// # Safety
/// `ctx` is NULL or a live `BN_CTX`.
pub(crate) unsafe fn random(
    ctx: *const BN_CTX,
    libctx: *mut OSSL_LIB_CTX,
) -> impl FnMut(&mut [u8]) -> bool {
    let lc = if ctx.is_null() {
        libctx
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { crate::bn::ctx::libctx_of(ctx) }
    };
    crate::rsa::private_random(lc)
}

ffi_export! {
    /// `EC_GFp_simple_method`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EC_GFp_simple_method() -> *const EC_METHOD
    where failure = core::ptr::null(), library = ERR_LIB_EC
    {
        method_ptr(Meth::Simple)
    }
}

ffi_export! {
    /// `EC_GFp_mont_method`: the prime-field method of explicit and most named curves.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EC_GFp_mont_method() -> *const EC_METHOD
    where failure = core::ptr::null(), library = ERR_LIB_EC
    {
        method_ptr(Meth::Mont)
    }
}

ffi_export! {
    /// `EC_GFp_nist_method`: for the NIST primes only.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EC_GFp_nist_method() -> *const EC_METHOD
    where failure = core::ptr::null(), library = ERR_LIB_EC
    {
        method_ptr(Meth::Nist)
    }
}

ffi_export! {
    /// `EC_GFp_nistp224_method`: for P-224 only.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EC_GFp_nistp224_method() -> *const EC_METHOD
    where failure = core::ptr::null(), library = ERR_LIB_EC
    {
        method_ptr(Meth::Nistp224)
    }
}

ffi_export! {
    /// `EC_GFp_nistp256_method`: for P-256 only.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EC_GFp_nistp256_method() -> *const EC_METHOD
    where failure = core::ptr::null(), library = ERR_LIB_EC
    {
        method_ptr(Meth::Nistp256)
    }
}

ffi_export! {
    /// `EC_GFp_nistp521_method`: for P-521 only.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EC_GFp_nistp521_method() -> *const EC_METHOD
    where failure = core::ptr::null(), library = ERR_LIB_EC
    {
        method_ptr(Meth::Nistp521)
    }
}

ffi_export! {
    /// `EC_GF2m_simple_method`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EC_GF2m_simple_method() -> *const EC_METHOD
    where failure = core::ptr::null(), library = ERR_LIB_EC
    {
        method_ptr(Meth::Gf2m)
    }
}

ffi_export! {
    /// The method's field type: `NID_X9_62_prime_field` or
    /// `NID_X9_62_characteristic_two_field`.
    ///
    /// # Safety
    /// `meth` is a method.
    pub unsafe extern "C" fn EC_METHOD_get_field_type(meth: *const EC_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { method_of(meth) }.map_or(0, field_type)
    }
}
