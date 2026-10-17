//! Time specifications (`v3_timespec.c`; ITU-T X.520's TimeSpecification): the time
//! specification extension of attribute certificates, an absolute time or periods (bands of
//! the day, days, weeks, months, and years), and the time zone.
//!
//! As OpenSSL's printing:
//! - An absolute time with only a start prints the start twice, as a date and as it's encoded.
//! - A named day of a period's `dayOf` that's a SET OF ENUMERATED doesn't print: OpenSSL reads
//!   the set as one INTEGER, which fails (`ASN1_R_WRONG_INTEGER_TYPE`), and so does this.
//! - A day, week, or month number without a name fails.

use core::ffi::{c_int, c_void};
use core::mem::offset_of;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_INTEGER, ASN1_ITEM, ASN1_R_WRONG_INTEGER_TYPE, ASN1_STRING,
    ASN1_TFLG_EXPLICIT, ASN1_TFLG_OPTIONAL, ASN1_TFLG_SET_OF, BIO, ERR_LIB_ASN1, ERR_LIB_X509V3,
    NID_time_specification, OSSL_DAY_TIME, OSSL_DAY_TIME_BAND, OSSL_NAMED_DAY,
    OSSL_NAMED_DAY_TYPE_BIT, OSSL_NAMED_DAY_TYPE_INT, OSSL_TIME_PERIOD, OSSL_TIME_SPEC,
    OSSL_TIME_SPEC_ABSOLUTE, OSSL_TIME_SPEC_BIT_MONTH_DEC, OSSL_TIME_SPEC_BIT_MONTH_JAN,
    OSSL_TIME_SPEC_BIT_WEEKS_1, OSSL_TIME_SPEC_BIT_WEEKS_5, OSSL_TIME_SPEC_DAY,
    OSSL_TIME_SPEC_DAY_BIT_SAT, OSSL_TIME_SPEC_DAY_BIT_SUN, OSSL_TIME_SPEC_DAY_INT_SUN,
    OSSL_TIME_SPEC_DAY_TYPE_BIT, OSSL_TIME_SPEC_DAY_TYPE_DAY_OF, OSSL_TIME_SPEC_DAY_TYPE_INT,
    OSSL_TIME_SPEC_INT_MONTH_JAN, OSSL_TIME_SPEC_MONTH, OSSL_TIME_SPEC_MONTH_TYPE_ALL,
    OSSL_TIME_SPEC_MONTH_TYPE_BIT, OSSL_TIME_SPEC_MONTH_TYPE_INT, OSSL_TIME_SPEC_TIME,
    OSSL_TIME_SPEC_TIME_TYPE_ABSOLUTE, OSSL_TIME_SPEC_TIME_TYPE_PERIODIC, OSSL_TIME_SPEC_WEEKS,
    OSSL_TIME_SPEC_WEEKS_TYPE_ALL, OSSL_TIME_SPEC_WEEKS_TYPE_BIT, OSSL_TIME_SPEC_WEEKS_TYPE_INT,
    OSSL_TIME_SPEC_X_DAY_OF, OSSL_TIME_SPEC_X_DAY_OF_FIFTH, OSSL_TIME_SPEC_X_DAY_OF_FIRST,
    OSSL_TIME_SPEC_X_DAY_OF_FOURTH, OSSL_TIME_SPEC_X_DAY_OF_SECOND, OSSL_TIME_SPEC_X_DAY_OF_THIRD,
    X509V3_EXT_METHOD, X509V3_EXT_MULTILINE, stack_st_ASN1_INTEGER,
};

use super::registry::{Method, method};
use super::text::Out;
use crate::asn1::bit_string::ASN1_BIT_STRING_get_bit;
use crate::asn1::integer::ASN1_INTEGER_get_int64;
use crate::asn1::time::print_time;
use crate::asn1::tpl::items::{
    ASN1_BIT_STRING_it, ASN1_ENUMERATED_it, ASN1_FBOOLEAN_it, ASN1_GENERALIZEDTIME_it,
    ASN1_INTEGER_it, ASN1_NULL_it, d2i, i2d, new_free,
};
use crate::asn1::tpl::statics::{Templates, choice, sequence};
use crate::asn1::tpl::{item_fns, template_at};
use crate::err;
use crate::ffi::ffi_callback;
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_value};

// The items.

static ABSOLUTE_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(OSSL_TIME_SPEC_ABSOLUTE, startTime),
        c"startTime",
        ASN1_GENERALIZEDTIME_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(OSSL_TIME_SPEC_ABSOLUTE, endTime),
        c"endTime",
        ASN1_GENERALIZEDTIME_it,
    ),
]);

item_fns! {
    /// An absolute time: [0] start and [1] end GeneralizedTimes, each optional.
    pub unsafe extern "C" fn OSSL_TIME_SPEC_ABSOLUTE_it = sequence::<OSSL_TIME_SPEC_ABSOLUTE, 2>(&ABSOLUTE_TT, None, c"OSSL_TIME_SPEC_ABSOLUTE");
}

new_free! {
    pub unsafe extern "C" fn OSSL_TIME_SPEC_ABSOLUTE_new, pub unsafe extern "C" fn OSSL_TIME_SPEC_ABSOLUTE_free(OSSL_TIME_SPEC_ABSOLUTE) = OSSL_TIME_SPEC_ABSOLUTE_it;
}

i2d! {
    /// Encodes an `OSSL_TIME_SPEC_ABSOLUTE`.
    pub unsafe extern "C" fn i2d_OSSL_TIME_SPEC_ABSOLUTE(OSSL_TIME_SPEC_ABSOLUTE) = OSSL_TIME_SPEC_ABSOLUTE_it;
}

d2i! {
    /// Decodes an `OSSL_TIME_SPEC_ABSOLUTE` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_TIME_SPEC_ABSOLUTE(OSSL_TIME_SPEC_ABSOLUTE) = OSSL_TIME_SPEC_ABSOLUTE_it;
}

static DAY_TIME_TT: Templates<3> = Templates([
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(OSSL_DAY_TIME, hour),
        c"hour",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(OSSL_DAY_TIME, minute),
        c"minute",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        2,
        offset_of!(OSSL_DAY_TIME, second),
        c"second",
        ASN1_INTEGER_it,
    ),
]);

item_fns! {
    /// A time of day: [0] hour, [1] minute, and [2] second, each optional.
    pub unsafe extern "C" fn OSSL_DAY_TIME_it = sequence::<OSSL_DAY_TIME, 3>(&DAY_TIME_TT, None, c"OSSL_DAY_TIME");
}

new_free! {
    pub unsafe extern "C" fn OSSL_DAY_TIME_new, pub unsafe extern "C" fn OSSL_DAY_TIME_free(OSSL_DAY_TIME) = OSSL_DAY_TIME_it;
}

i2d! {
    /// Encodes an `OSSL_DAY_TIME`.
    pub unsafe extern "C" fn i2d_OSSL_DAY_TIME(OSSL_DAY_TIME) = OSSL_DAY_TIME_it;
}

d2i! {
    /// Decodes an `OSSL_DAY_TIME` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_DAY_TIME(OSSL_DAY_TIME) = OSSL_DAY_TIME_it;
}

static DAY_TIME_BAND_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(OSSL_DAY_TIME_BAND, startDayTime),
        c"startDayTime",
        OSSL_DAY_TIME_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(OSSL_DAY_TIME_BAND, endDayTime),
        c"endDayTime",
        OSSL_DAY_TIME_it,
    ),
]);

item_fns! {
    /// A band of the day: [0] start and [1] end times of day, each optional.
    pub unsafe extern "C" fn OSSL_DAY_TIME_BAND_it = sequence::<OSSL_DAY_TIME_BAND, 2>(&DAY_TIME_BAND_TT, None, c"OSSL_DAY_TIME_BAND");
}

new_free! {
    pub unsafe extern "C" fn OSSL_DAY_TIME_BAND_new, pub unsafe extern "C" fn OSSL_DAY_TIME_BAND_free(OSSL_DAY_TIME_BAND) = OSSL_DAY_TIME_BAND_it;
}

i2d! {
    /// Encodes an `OSSL_DAY_TIME_BAND`.
    pub unsafe extern "C" fn i2d_OSSL_DAY_TIME_BAND(OSSL_DAY_TIME_BAND) = OSSL_DAY_TIME_BAND_it;
}

d2i! {
    /// Decodes an `OSSL_DAY_TIME_BAND` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_DAY_TIME_BAND(OSSL_DAY_TIME_BAND) = OSSL_DAY_TIME_BAND_it;
}

static NAMED_DAY_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_SET_OF,
        0,
        offset_of!(OSSL_NAMED_DAY, choice),
        c"choice.intNamedDays",
        ASN1_ENUMERATED_it,
    ),
    template_at(
        0,
        0,
        offset_of!(OSSL_NAMED_DAY, choice),
        c"choice.bitNamedDays",
        ASN1_BIT_STRING_it,
    ),
]);

item_fns! {
    /// A named day: a SET OF ENUMERATED days, or a BIT STRING of them.
    pub unsafe extern "C" fn OSSL_NAMED_DAY_it = choice::<OSSL_NAMED_DAY, 2>(&NAMED_DAY_TT, offset_of!(OSSL_NAMED_DAY, type_), None, c"OSSL_NAMED_DAY");
}

new_free! {
    pub unsafe extern "C" fn OSSL_NAMED_DAY_new, pub unsafe extern "C" fn OSSL_NAMED_DAY_free(OSSL_NAMED_DAY) = OSSL_NAMED_DAY_it;
}

i2d! {
    /// Encodes an `OSSL_NAMED_DAY`.
    pub unsafe extern "C" fn i2d_OSSL_NAMED_DAY(OSSL_NAMED_DAY) = OSSL_NAMED_DAY_it;
}

d2i! {
    /// Decodes an `OSSL_NAMED_DAY` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_NAMED_DAY(OSSL_NAMED_DAY) = OSSL_NAMED_DAY_it;
}

static X_DAY_OF_TT: Templates<5> = Templates([
    template_at(
        ASN1_TFLG_EXPLICIT,
        1,
        offset_of!(OSSL_TIME_SPEC_X_DAY_OF, choice),
        c"choice.first",
        OSSL_NAMED_DAY_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT,
        2,
        offset_of!(OSSL_TIME_SPEC_X_DAY_OF, choice),
        c"choice.second",
        OSSL_NAMED_DAY_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT,
        3,
        offset_of!(OSSL_TIME_SPEC_X_DAY_OF, choice),
        c"choice.third",
        OSSL_NAMED_DAY_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT,
        4,
        offset_of!(OSSL_TIME_SPEC_X_DAY_OF, choice),
        c"choice.fourth",
        OSSL_NAMED_DAY_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT,
        5,
        offset_of!(OSSL_TIME_SPEC_X_DAY_OF, choice),
        c"choice.fifth",
        OSSL_NAMED_DAY_it,
    ),
]);

item_fns! {
    /// The [1] first to [5] fifth named day of a period.
    pub unsafe extern "C" fn OSSL_TIME_SPEC_X_DAY_OF_it = choice::<OSSL_TIME_SPEC_X_DAY_OF, 5>(&X_DAY_OF_TT, offset_of!(OSSL_TIME_SPEC_X_DAY_OF, type_), None, c"OSSL_TIME_SPEC_X_DAY_OF");
}

new_free! {
    pub unsafe extern "C" fn OSSL_TIME_SPEC_X_DAY_OF_new, pub unsafe extern "C" fn OSSL_TIME_SPEC_X_DAY_OF_free(OSSL_TIME_SPEC_X_DAY_OF) = OSSL_TIME_SPEC_X_DAY_OF_it;
}

i2d! {
    /// Encodes an `OSSL_TIME_SPEC_X_DAY_OF`.
    pub unsafe extern "C" fn i2d_OSSL_TIME_SPEC_X_DAY_OF(OSSL_TIME_SPEC_X_DAY_OF) = OSSL_TIME_SPEC_X_DAY_OF_it;
}

d2i! {
    /// Decodes an `OSSL_TIME_SPEC_X_DAY_OF` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_TIME_SPEC_X_DAY_OF(OSSL_TIME_SPEC_X_DAY_OF) = OSSL_TIME_SPEC_X_DAY_OF_it;
}

static SPEC_DAY_TT: Templates<3> = Templates([
    template_at(
        ASN1_TFLG_SET_OF,
        0,
        offset_of!(OSSL_TIME_SPEC_DAY, choice),
        c"choice.intDay",
        ASN1_INTEGER_it,
    ),
    template_at(
        0,
        0,
        offset_of!(OSSL_TIME_SPEC_DAY, choice),
        c"choice.bitDay",
        ASN1_BIT_STRING_it,
    ),
    template_at(
        0,
        0,
        offset_of!(OSSL_TIME_SPEC_DAY, choice),
        c"choice.dayOf",
        OSSL_TIME_SPEC_X_DAY_OF_it,
    ),
]);

item_fns! {
    /// The days of a period: a SET OF INTEGER, a BIT STRING, or a day of.
    pub unsafe extern "C" fn OSSL_TIME_SPEC_DAY_it = choice::<OSSL_TIME_SPEC_DAY, 3>(&SPEC_DAY_TT, offset_of!(OSSL_TIME_SPEC_DAY, type_), None, c"OSSL_TIME_SPEC_DAY");
}

new_free! {
    pub unsafe extern "C" fn OSSL_TIME_SPEC_DAY_new, pub unsafe extern "C" fn OSSL_TIME_SPEC_DAY_free(OSSL_TIME_SPEC_DAY) = OSSL_TIME_SPEC_DAY_it;
}

i2d! {
    /// Encodes an `OSSL_TIME_SPEC_DAY`.
    pub unsafe extern "C" fn i2d_OSSL_TIME_SPEC_DAY(OSSL_TIME_SPEC_DAY) = OSSL_TIME_SPEC_DAY_it;
}

d2i! {
    /// Decodes an `OSSL_TIME_SPEC_DAY` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_TIME_SPEC_DAY(OSSL_TIME_SPEC_DAY) = OSSL_TIME_SPEC_DAY_it;
}

static WEEKS_TT: Templates<3> = Templates([
    template_at(
        0,
        0,
        offset_of!(OSSL_TIME_SPEC_WEEKS, choice),
        c"choice.allWeeks",
        ASN1_NULL_it,
    ),
    template_at(
        ASN1_TFLG_SET_OF,
        0,
        offset_of!(OSSL_TIME_SPEC_WEEKS, choice),
        c"choice.intWeek",
        ASN1_INTEGER_it,
    ),
    template_at(
        0,
        0,
        offset_of!(OSSL_TIME_SPEC_WEEKS, choice),
        c"choice.bitWeek",
        ASN1_BIT_STRING_it,
    ),
]);

item_fns! {
    /// The weeks of a period: all (NULL), a SET OF INTEGER, or a BIT STRING.
    pub unsafe extern "C" fn OSSL_TIME_SPEC_WEEKS_it = choice::<OSSL_TIME_SPEC_WEEKS, 3>(&WEEKS_TT, offset_of!(OSSL_TIME_SPEC_WEEKS, type_), None, c"OSSL_TIME_SPEC_WEEKS");
}

new_free! {
    pub unsafe extern "C" fn OSSL_TIME_SPEC_WEEKS_new, pub unsafe extern "C" fn OSSL_TIME_SPEC_WEEKS_free(OSSL_TIME_SPEC_WEEKS) = OSSL_TIME_SPEC_WEEKS_it;
}

i2d! {
    /// Encodes an `OSSL_TIME_SPEC_WEEKS`.
    pub unsafe extern "C" fn i2d_OSSL_TIME_SPEC_WEEKS(OSSL_TIME_SPEC_WEEKS) = OSSL_TIME_SPEC_WEEKS_it;
}

d2i! {
    /// Decodes an `OSSL_TIME_SPEC_WEEKS` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_TIME_SPEC_WEEKS(OSSL_TIME_SPEC_WEEKS) = OSSL_TIME_SPEC_WEEKS_it;
}

static MONTH_TT: Templates<3> = Templates([
    template_at(
        0,
        0,
        offset_of!(OSSL_TIME_SPEC_MONTH, choice),
        c"choice.allMonths",
        ASN1_NULL_it,
    ),
    template_at(
        ASN1_TFLG_SET_OF,
        0,
        offset_of!(OSSL_TIME_SPEC_MONTH, choice),
        c"choice.intMonth",
        ASN1_INTEGER_it,
    ),
    template_at(
        0,
        0,
        offset_of!(OSSL_TIME_SPEC_MONTH, choice),
        c"choice.bitMonth",
        ASN1_BIT_STRING_it,
    ),
]);

item_fns! {
    /// The months of a period: all (NULL), a SET OF INTEGER, or a BIT STRING.
    pub unsafe extern "C" fn OSSL_TIME_SPEC_MONTH_it = choice::<OSSL_TIME_SPEC_MONTH, 3>(&MONTH_TT, offset_of!(OSSL_TIME_SPEC_MONTH, type_), None, c"OSSL_TIME_SPEC_MONTH");
}

new_free! {
    pub unsafe extern "C" fn OSSL_TIME_SPEC_MONTH_new, pub unsafe extern "C" fn OSSL_TIME_SPEC_MONTH_free(OSSL_TIME_SPEC_MONTH) = OSSL_TIME_SPEC_MONTH_it;
}

i2d! {
    /// Encodes an `OSSL_TIME_SPEC_MONTH`.
    pub unsafe extern "C" fn i2d_OSSL_TIME_SPEC_MONTH(OSSL_TIME_SPEC_MONTH) = OSSL_TIME_SPEC_MONTH_it;
}

d2i! {
    /// Decodes an `OSSL_TIME_SPEC_MONTH` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_TIME_SPEC_MONTH(OSSL_TIME_SPEC_MONTH) = OSSL_TIME_SPEC_MONTH_it;
}

static PERIOD_TT: Templates<5> = Templates([
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(OSSL_TIME_PERIOD, timesOfDay),
        c"timesOfDay",
        OSSL_DAY_TIME_BAND_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(OSSL_TIME_PERIOD, days),
        c"days",
        OSSL_TIME_SPEC_DAY_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        2,
        offset_of!(OSSL_TIME_PERIOD, weeks),
        c"weeks",
        OSSL_TIME_SPEC_WEEKS_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        3,
        offset_of!(OSSL_TIME_PERIOD, months),
        c"months",
        OSSL_TIME_SPEC_MONTH_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        4,
        offset_of!(OSSL_TIME_PERIOD, years),
        c"years",
        ASN1_INTEGER_it,
    ),
]);

item_fns! {
    /// A period: [0] bands of the day, [1] days, [2] weeks, [3] months, and [4] years, each optional.
    pub unsafe extern "C" fn OSSL_TIME_PERIOD_it = sequence::<OSSL_TIME_PERIOD, 5>(&PERIOD_TT, None, c"OSSL_TIME_PERIOD");
}

new_free! {
    pub unsafe extern "C" fn OSSL_TIME_PERIOD_new, pub unsafe extern "C" fn OSSL_TIME_PERIOD_free(OSSL_TIME_PERIOD) = OSSL_TIME_PERIOD_it;
}

i2d! {
    /// Encodes an `OSSL_TIME_PERIOD`.
    pub unsafe extern "C" fn i2d_OSSL_TIME_PERIOD(OSSL_TIME_PERIOD) = OSSL_TIME_PERIOD_it;
}

d2i! {
    /// Decodes an `OSSL_TIME_PERIOD` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_TIME_PERIOD(OSSL_TIME_PERIOD) = OSSL_TIME_PERIOD_it;
}

static SPEC_TIME_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(OSSL_TIME_SPEC_TIME, choice),
        c"choice.absolute",
        OSSL_TIME_SPEC_ABSOLUTE_it,
    ),
    template_at(
        ASN1_TFLG_SET_OF,
        0,
        offset_of!(OSSL_TIME_SPEC_TIME, choice),
        c"choice.periodic",
        OSSL_TIME_PERIOD_it,
    ),
]);

item_fns! {
    /// A time: absolute, or a SET OF periods.
    pub unsafe extern "C" fn OSSL_TIME_SPEC_TIME_it = choice::<OSSL_TIME_SPEC_TIME, 2>(&SPEC_TIME_TT, offset_of!(OSSL_TIME_SPEC_TIME, type_), None, c"OSSL_TIME_SPEC_TIME");
}

new_free! {
    pub unsafe extern "C" fn OSSL_TIME_SPEC_TIME_new, pub unsafe extern "C" fn OSSL_TIME_SPEC_TIME_free(OSSL_TIME_SPEC_TIME) = OSSL_TIME_SPEC_TIME_it;
}

i2d! {
    /// Encodes an `OSSL_TIME_SPEC_TIME`.
    pub unsafe extern "C" fn i2d_OSSL_TIME_SPEC_TIME(OSSL_TIME_SPEC_TIME) = OSSL_TIME_SPEC_TIME_it;
}

d2i! {
    /// Decodes an `OSSL_TIME_SPEC_TIME` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_TIME_SPEC_TIME(OSSL_TIME_SPEC_TIME) = OSSL_TIME_SPEC_TIME_it;
}

static SPEC_TT: Templates<3> = Templates([
    template_at(
        0,
        0,
        offset_of!(OSSL_TIME_SPEC, time),
        c"time",
        OSSL_TIME_SPEC_TIME_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(OSSL_TIME_SPEC, notThisTime),
        c"notThisTime",
        ASN1_FBOOLEAN_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(OSSL_TIME_SPEC, timeZone),
        c"timeZone",
        ASN1_INTEGER_it,
    ),
]);

item_fns! {
    /// A time specification: the time, notThisTime (BOOLEAN DEFAULT FALSE), and an optional time zone.
    pub unsafe extern "C" fn OSSL_TIME_SPEC_it = sequence::<OSSL_TIME_SPEC, 3>(&SPEC_TT, None, c"OSSL_TIME_SPEC");
}

new_free! {
    pub unsafe extern "C" fn OSSL_TIME_SPEC_new, pub unsafe extern "C" fn OSSL_TIME_SPEC_free(OSSL_TIME_SPEC) = OSSL_TIME_SPEC_it;
}

i2d! {
    /// Encodes an `OSSL_TIME_SPEC`.
    pub unsafe extern "C" fn i2d_OSSL_TIME_SPEC(OSSL_TIME_SPEC) = OSSL_TIME_SPEC_it;
}

d2i! {
    /// Decodes an `OSSL_TIME_SPEC` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_TIME_SPEC(OSSL_TIME_SPEC) = OSSL_TIME_SPEC_it;
}

// Printing.

/// An INTEGER's value, or `None` (with `ASN1_INTEGER_get_int64`'s error).
///
/// # Safety
/// `a` is NULL or a live INTEGER.
unsafe fn int64(a: *const ASN1_INTEGER) -> Option<i64> {
    let mut v: i64 = 0;
    // SAFETY: a local; the caller's guarantee.
    (unsafe { ASN1_INTEGER_get_int64(&raw mut v, a) } == 1).then_some(v)
}

/// Each INTEGER of the stack, comma separated, printed by `each`; false if one doesn't read
/// or print.
///
/// # Safety
/// `sk` is NULL or a live stack of INTEGERs.
unsafe fn print_ints(
    out: Out,
    sk: *const stack_st_ASN1_INTEGER,
    each: impl Fn(i64) -> bool,
) -> bool {
    // SAFETY: the caller's guarantee.
    let n = unsafe { OPENSSL_sk_num(sk.cast()) };
    for i in 0..n {
        // SAFETY: an index within the stack.
        let a = unsafe { OPENSSL_sk_value(sk.cast(), i) };
        // SAFETY: an INTEGER of the stack.
        let Some(v) = (unsafe { int64(a.cast()) }) else {
            return false;
        };
        if i > 0 && out.print(", ") <= 0 {
            return false;
        }
        if !each(v) {
            return false;
        }
    }
    true
}

const WEEKDAY_NAMES: [&str; 7] = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];
const WEEK_NAMES: [&str; 5] = ["first", "second", "third", "fourth", "final"];
/// For a BIT STRING of months; numbers name September `SEP`.
const MONTH_NAMES: [&str; 12] = [
    "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEPT", "OCT", "NOV", "DEC",
];
const INT_MONTH_NAMES: [&str; 12] = [
    "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
];

/// The name of number `v` (`print_int_month` and the others), of names numbered from
/// `first`: false for none.
fn print_int_name(out: Out, names: &[&str], first: c_int, v: i64) -> bool {
    let name = v
        .checked_sub(i64::from(first))
        .and_then(|i| usize::try_from(i).ok())
        .and_then(|i| names.get(i));
    name.is_some_and(|n| out.print(n) > 0)
}

/// The names of the bits `first..=last` set, comma separated (`print_bit_month` and the
/// others); the bits index `names`.
///
/// # Safety
/// `bs` is NULL or a live BIT STRING.
unsafe fn print_bits(
    out: Out,
    bs: *const ASN1_BIT_STRING,
    names: &[&str],
    first: c_int,
    last: c_int,
) -> bool {
    let mut j = 0;
    for i in first..=last {
        // SAFETY: the caller's guarantee.
        if unsafe { ASN1_BIT_STRING_get_bit(bs, i) } == 0 {
            continue;
        }
        if j > 0 && out.print(", ") <= 0 {
            return false;
        }
        j += 1;
        let name = usize::try_from(i).ok().and_then(|k| names.get(k));
        if !name.is_some_and(|n| out.print(n) > 0) {
            return false;
        }
    }
    true
}

/// `print_day_of_week`.
///
/// # Safety
/// As for [`print_bits`].
unsafe fn print_day_of_week(out: Out, bs: *const ASN1_BIT_STRING) -> bool {
    let (first, last) = (OSSL_TIME_SPEC_DAY_BIT_SUN, OSSL_TIME_SPEC_DAY_BIT_SAT);
    // SAFETY: the caller's guarantee.
    unsafe { print_bits(out, bs, &WEEKDAY_NAMES, first, last) }
}

/// `ossl_asn1_time_print_ex(out, t, 0)`, which fails only for 0 (a bad time prints and
/// returns -1).
///
/// # Safety
/// `t` is a live time.
unsafe fn time(out: Out, t: *const ASN1_STRING) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { print_time(out.bio(), t, 0) != 0 }
}

/// `i2r_OSSL_TIME_SPEC_ABSOLUTE`.
///
/// # Safety
/// `a` is NULL or a live absolute time.
unsafe fn print_absolute(out: Out, a: *const OSSL_TIME_SPEC_ABSOLUTE) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(a) = (unsafe { a.as_ref() }) else {
        return 0;
    };
    let (start, end) = (a.startTime.cast_const(), a.endTime.cast_const());
    // The times are live when set.
    let ok = match (start.is_null(), end.is_null()) {
        (false, false) => {
            out.print("Any time between ") > 0
                // SAFETY: as above.
                && unsafe { time(out, start) }
                && out.print(" and ") > 0
                // SAFETY: as above.
                && unsafe { time(out, end) }
        }
        (false, true) => {
            out.print("Any time after ") > 0
                // SAFETY: as above.
                && unsafe { time(out, start) }
                // SAFETY: as above.
                && unsafe { out.line_string(0, start) } > 0
        }
        // SAFETY: as above.
        (true, false) => out.print("Any time until ") > 0 && unsafe { time(out, end) },
        (true, true) => return out.print("INVALID (EMPTY)"),
    };
    c_int::from(ok)
}

/// `i2r_OSSL_DAY_TIME`: `hh:mm:ss`; the hour must be there.
///
/// # Safety
/// The time's INTEGERs are NULL or live.
unsafe fn print_day_time(out: Out, dt: &OSSL_DAY_TIME) -> bool {
    if dt.hour.is_null() {
        return false;
    }
    let mut hms = [0i64; 3];
    for (v, a) in hms.iter_mut().zip([dt.hour, dt.minute, dt.second]) {
        if !a.is_null() {
            // SAFETY: the caller's guarantee.
            let Some(x) = (unsafe { int64(a) }) else {
                return false;
            };
            *v = x;
        }
    }
    let [h, m, s] = hms;
    out.print(&format!("{h:02}:{m:02}:{s:02}")) > 0
}

/// `i2r_OSSL_DAY_TIME_BAND`: `start - end`, the day's start and end by default.
///
/// # Safety
/// The band's times are NULL or live.
unsafe fn print_band(out: Out, band: &OSSL_DAY_TIME_BAND) -> bool {
    // SAFETY: the caller's guarantee.
    let start = match unsafe { band.startDayTime.as_ref() } {
        // SAFETY: as above.
        Some(t) => unsafe { print_day_time(out, t) },
        None => out.print("00:00:00") > 0,
    };
    // SAFETY: as above.
    let end = || match unsafe { band.endDayTime.as_ref() } {
        // SAFETY: as above.
        Some(t) => unsafe { print_day_time(out, t) },
        None => out.print("23:59:59") > 0,
    };
    start && out.print(" - ") > 0 && end()
}

/// A named day: its bits by name. A SET OF numbers doesn't print, as OpenSSL's (see the
/// module's comment).
///
/// # Safety
/// The named day's member is live.
unsafe fn print_named_day(out: Out, nd: &OSSL_NAMED_DAY) -> bool {
    match nd.type_ {
        t if t == OSSL_NAMED_DAY_TYPE_INT => {
            // OpenSSL reads the stack as an INTEGER, whose type is then 0.
            err::raise(
                ERR_LIB_ASN1,
                ASN1_R_WRONG_INTEGER_TYPE,
                "asn1_string_get_int64",
            );
            false
        }
        t if t == OSSL_NAMED_DAY_TYPE_BIT => {
            // SAFETY: the choice's member.
            let bs = unsafe { nd.choice.bitNamedDays };
            // SAFETY: the caller's guarantee.
            unsafe { print_day_of_week(out, bs) }
        }
        _ => false,
    }
}

/// The named day of a `dayOf`: `FIRST ` to `FIFTH `, then the day.
///
/// # Safety
/// The day of's member and the named day's are live.
unsafe fn print_day_of(out: Out, d: &OSSL_TIME_SPEC_X_DAY_OF) -> bool {
    let which = match d.type_ {
        t if t == OSSL_TIME_SPEC_X_DAY_OF_FIRST => "FIRST ",
        t if t == OSSL_TIME_SPEC_X_DAY_OF_SECOND => "SECOND ",
        t if t == OSSL_TIME_SPEC_X_DAY_OF_THIRD => "THIRD ",
        t if t == OSSL_TIME_SPEC_X_DAY_OF_FOURTH => "FOURTH ",
        t if t == OSSL_TIME_SPEC_X_DAY_OF_FIFTH => "FIFTH ",
        _ => return false,
    };
    if out.print(which) <= 0 {
        return false;
    }
    // Each of the union's members is the named day.
    // SAFETY: the choice's member.
    let nd = unsafe { d.choice.first };
    // SAFETY: the caller's guarantee.
    match unsafe { nd.as_ref() } {
        // SAFETY: as above.
        Some(nd) => unsafe { print_named_day(out, nd) },
        None => false,
    }
}

/// The days of a period, with their heading.
///
/// # Safety
/// The days' members are live.
unsafe fn print_days(
    out: Out,
    p: &OSSL_TIME_PERIOD,
    days: &OSSL_TIME_SPEC_DAY,
    indent: c_int,
) -> bool {
    let ind = indent.saturating_add(4);
    let heading = if days.type_ == OSSL_TIME_SPEC_DAY_TYPE_INT {
        if !p.weeks.is_null() {
            Some("Days of the week: ")
        } else if !p.months.is_null() {
            Some("Days of the month: ")
        } else if !p.years.is_null() {
            Some("Days of the year: ")
        } else {
            None
        }
    } else {
        Some("Days: ")
    };
    if heading.is_some_and(|h| out.line(ind, h) <= 0) {
        return false;
    }
    let ok = match days.type_ {
        t if t == OSSL_TIME_SPEC_DAY_TYPE_INT => {
            // SAFETY: the choice's member.
            let sk = unsafe { days.choice.intDay };
            let weekly = !p.weeks.is_null();
            let each = |v| {
                if weekly {
                    print_int_name(out, &WEEKDAY_NAMES, OSSL_TIME_SPEC_DAY_INT_SUN, v)
                } else {
                    out.print(&v.to_string()) > 0
                }
            };
            // SAFETY: the caller's guarantee.
            unsafe { print_ints(out, sk, each) }
        }
        t if t == OSSL_TIME_SPEC_DAY_TYPE_BIT => {
            // SAFETY: the choice's member.
            let bs = unsafe { days.choice.bitDay };
            // SAFETY: the caller's guarantee.
            unsafe { print_day_of_week(out, bs) }
        }
        t if t == OSSL_TIME_SPEC_DAY_TYPE_DAY_OF => {
            // SAFETY: the choice's member.
            let d = unsafe { days.choice.dayOf };
            // SAFETY: the caller's guarantee.
            match unsafe { d.as_ref() } {
                // SAFETY: as above.
                Some(d) => unsafe { print_day_of(out, d) },
                None => false,
            }
        }
        _ => false,
    };
    ok && out.print("\n") > 0
}

/// The weeks of a period, with their heading.
///
/// # Safety
/// The weeks' members are live.
unsafe fn print_weeks(
    out: Out,
    p: &OSSL_TIME_PERIOD,
    weeks: &OSSL_TIME_SPEC_WEEKS,
    indent: c_int,
) -> bool {
    let heading = if weeks.type_ == OSSL_TIME_SPEC_WEEKS_TYPE_INT {
        if !p.months.is_null() {
            Some("Weeks of the month: ")
        } else if !p.years.is_null() {
            Some("Weeks of the year: ")
        } else {
            None
        }
    } else {
        Some("Weeks: ")
    };
    if heading.is_some_and(|h| out.line(indent.saturating_add(4), h) <= 0) {
        return false;
    }
    let ok = match weeks.type_ {
        t if t == OSSL_TIME_SPEC_WEEKS_TYPE_ALL => out.print("ALL") > 0,
        t if t == OSSL_TIME_SPEC_WEEKS_TYPE_INT => {
            // SAFETY: the choice's member.
            let sk = unsafe { weeks.choice.intWeek };
            // SAFETY: the caller's guarantee.
            unsafe { print_ints(out, sk, |v| out.print(&v.to_string()) != 0) }
        }
        t if t == OSSL_TIME_SPEC_WEEKS_TYPE_BIT => {
            // SAFETY: the choice's member.
            let bs = unsafe { weeks.choice.bitWeek };
            let (first, last) = (OSSL_TIME_SPEC_BIT_WEEKS_1, OSSL_TIME_SPEC_BIT_WEEKS_5);
            // SAFETY: the caller's guarantee.
            unsafe { print_bits(out, bs, &WEEK_NAMES, first, last) }
        }
        _ => false,
    };
    ok && out.print("\n") > 0
}

/// The months of a period, with their heading.
///
/// # Safety
/// The months' members are live.
unsafe fn print_months(out: Out, months: &OSSL_TIME_SPEC_MONTH, indent: c_int) -> bool {
    if out.line(indent.saturating_add(4), "Months: ") <= 0 {
        return false;
    }
    let ok = match months.type_ {
        t if t == OSSL_TIME_SPEC_MONTH_TYPE_ALL => out.print("ALL") > 0,
        t if t == OSSL_TIME_SPEC_MONTH_TYPE_INT => {
            // SAFETY: the choice's member.
            let sk = unsafe { months.choice.intMonth };
            let first = OSSL_TIME_SPEC_INT_MONTH_JAN;
            // SAFETY: the caller's guarantee.
            unsafe { print_ints(out, sk, |v| print_int_name(out, &INT_MONTH_NAMES, first, v)) }
        }
        t if t == OSSL_TIME_SPEC_MONTH_TYPE_BIT => {
            // SAFETY: the choice's member.
            let bs = unsafe { months.choice.bitMonth };
            let (first, last) = (OSSL_TIME_SPEC_BIT_MONTH_JAN, OSSL_TIME_SPEC_BIT_MONTH_DEC);
            // SAFETY: the caller's guarantee.
            unsafe { print_bits(out, bs, &MONTH_NAMES, first, last) }
        }
        _ => false,
    };
    ok && out.print("\n") > 0
}

/// `i2r_OSSL_PERIOD`: `Period:`, then each part that's set, `indent + 4` in; the years end
/// without a newline.
///
/// # Safety
/// The period's parts are NULL or live.
unsafe fn print_period(out: Out, p: &OSSL_TIME_PERIOD, indent: c_int) -> bool {
    if out.line(indent, "Period:\n") <= 0 {
        return false;
    }
    if !p.timesOfDay.is_null() {
        if out.line(indent.saturating_add(4), "Daytime bands:\n") <= 0 {
            return false;
        }
        // SAFETY: the caller's guarantee.
        let n = unsafe { OPENSSL_sk_num(p.timesOfDay.cast()) };
        for i in 0..n {
            // SAFETY: an index within the stack.
            let band = unsafe { OPENSSL_sk_value(p.timesOfDay.cast(), i) };
            // SAFETY: a band of the stack.
            let Some(band) = (unsafe { band.cast::<OSSL_DAY_TIME_BAND>().as_ref() }) else {
                return false;
            };
            if out.line(indent.saturating_add(8), "") < 0 {
                return false;
            }
            // SAFETY: as above.
            if !unsafe { print_band(out, band) } || out.print("\n") <= 0 {
                return false;
            }
        }
    }
    // SAFETY: the caller's guarantee.
    if let Some(days) = unsafe { p.days.as_ref() } {
        // SAFETY: as above.
        if !unsafe { print_days(out, p, days, indent) } {
            return false;
        }
    }
    // SAFETY: as above.
    if let Some(weeks) = unsafe { p.weeks.as_ref() } {
        // SAFETY: as above.
        if !unsafe { print_weeks(out, p, weeks, indent) } {
            return false;
        }
    }
    // SAFETY: as above.
    if let Some(months) = unsafe { p.months.as_ref() } {
        // SAFETY: as above.
        if !unsafe { print_months(out, months, indent) } {
            return false;
        }
    }
    if !p.years.is_null() {
        if out.line(indent.saturating_add(4), "Years: ") <= 0 {
            return false;
        }
        // SAFETY: as above.
        if !unsafe { print_ints(out, p.years, |v| out.print(&format!("{v:04}")) > 0) } {
            return false;
        }
    }
    true
}

/// `i2r_OSSL_TIME_SPEC_TIME`: `Absolute: …`, or `Periodic:` and each period.
///
/// # Safety
/// The time's member is live.
unsafe fn print_spec_time(out: Out, t: &OSSL_TIME_SPEC_TIME, indent: c_int) -> c_int {
    match t.type_ {
        k if k == OSSL_TIME_SPEC_TIME_TYPE_ABSOLUTE => {
            if out.line(indent, "Absolute: ") <= 0 {
                return 0;
            }
            // SAFETY: the choice's member.
            let a = unsafe { t.choice.absolute };
            // SAFETY: the caller's guarantee.
            if unsafe { print_absolute(out, a) } <= 0 {
                return 0;
            }
        }
        k if k == OSSL_TIME_SPEC_TIME_TYPE_PERIODIC => {
            if out.line(indent, "Periodic:\n") <= 0 {
                return 0;
            }
            // SAFETY: the choice's member.
            let sk = unsafe { t.choice.periodic };
            // SAFETY: the caller's guarantee.
            let n = unsafe { OPENSSL_sk_num(sk.cast()) };
            for i in 0..n {
                if i > 0 && out.print("\n") <= 0 {
                    return 0;
                }
                // SAFETY: an index within the stack.
                let tp = unsafe { OPENSSL_sk_value(sk.cast(), i) };
                // SAFETY: a period of the stack.
                let Some(tp) = (unsafe { tp.cast::<OSSL_TIME_PERIOD>().as_ref() }) else {
                    return 0;
                };
                // SAFETY: as above.
                if !unsafe { print_period(out, tp, indent.saturating_add(4)) } {
                    return 0;
                }
            }
        }
        _ => return 0,
    }
    out.print("\n")
}

ffi_callback! {
    /// `i2r_OSSL_TIME_SPEC`: the time zone if there's one, then `Time:` (`NOT this time:`) and
    /// the time.
    ///
    /// # Safety
    /// `ext` is a live time specification; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn time_spec_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let out = unsafe { Out::new(out) };
        // SAFETY: as above.
        let Some(ts) = (unsafe { ext.cast::<OSSL_TIME_SPEC>().as_ref() }) else { return 0 };
        if !ts.timeZone.is_null() {
            // SAFETY: its time zone.
            let Some(tz) = (unsafe { int64(ts.timeZone) }) else { return 0 };
            if out.line(indent, &format!("Timezone: UTC{tz:+03}:00\n")) <= 0 {
                return 0;
            }
        }
        let heading = if ts.notThisTime > 0 { "NOT this time:\n" } else { "Time:\n" };
        if out.line(indent, heading) <= 0 {
            return 0;
        }
        // SAFETY: its time, live when set.
        match unsafe { ts.time.as_ref() } {
            // SAFETY: as above.
            Some(t) => unsafe { print_spec_time(out, t, indent.saturating_add(4)) },
            None => 0,
        }
    }
}

pub(crate) static TIME_SPEC: Method = Method({
    let mut m = method(NID_time_specification, X509V3_EXT_MULTILINE);
    m.it = Some(OSSL_TIME_SPEC_it);
    m.i2r = Some(time_spec_i2r);
    m
});
