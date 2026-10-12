use super::*;

/// docs/DEVIATIONS.md: NULL numbers and contexts fail instead of crashing.
#[test]
fn null_numbers_fail() {
    let null = ptr::null_mut::<BIGNUM>();
    // SAFETY: no preconditions.
    let one = unsafe { BN_value_one() };
    // SAFETY: NULL is the case under test, here and below.
    assert_eq!(unsafe { BN_num_bits(null) }, 0);
    // SAFETY: as above.
    assert_eq!(unsafe { BN_is_zero(null) }, 0);
    // SAFETY: as above.
    assert_eq!(unsafe { BN_get_word(null) }, c_ulong::MAX);
    // SAFETY: as above.
    assert_eq!(unsafe { BN_set_word(null, 1) }, 0);
    // SAFETY: as above; `one` is live.
    assert!(unsafe { BN_copy(null, one) }.is_null());
    // SAFETY: as above.
    assert_eq!(unsafe { arith::BN_add(null, one, one) }, 0);
    // SAFETY: as above.
    assert_eq!(unsafe { arith::BN_div_word(null, 3) }, c_ulong::MAX);
    // SAFETY: as above.
    assert!(unsafe { conv::BN_bn2hex(null) }.is_null());
    // SAFETY: as above.
    unsafe { BN_free(null) };
    // SAFETY: as above.
    unsafe { ctx::BN_CTX_start(ptr::null_mut()) };
    // SAFETY: as above.
    unsafe { ctx::BN_CTX_end(ptr::null_mut()) };
    // SAFETY: as above.
    assert!(unsafe { ctx::BN_CTX_get(ptr::null_mut()) }.is_null());
    crate::err::take_all();
}

/// docs/DEVIATIONS.md: a number flagged `BN_FLG_STATIC_DATA` isn't written to.
#[test]
fn static_numbers_are_not_written() {
    // SAFETY: no preconditions.
    let one = unsafe { BN_value_one() }.cast_mut();
    // SAFETY: the constant one, here and below.
    assert_eq!(unsafe { BN_set_word(one, 5) }, 0);
    // SAFETY: as above.
    unsafe { BN_clear(one) };
    // SAFETY: as above.
    unsafe { BN_set_flags(one, BN_FLG_CONSTTIME) };
    // SAFETY: as above.
    unsafe { BN_free(one) };
    // SAFETY: as above.
    assert_eq!(unsafe { BN_is_one(one) }, 1);
    // SAFETY: as above.
    assert_eq!(unsafe { BN_get_flags(one, !0) }, BN_FLG_STATIC_DATA);
    // SAFETY: no preconditions.
    let b = unsafe { BN_new() };
    // SAFETY: the number just made and the constant one, here and below.
    unsafe { BN_with_flags(b, one, BN_FLG_CONSTTIME) };
    let flags = BN_FLG_MALLOCED | BN_FLG_STATIC_DATA | BN_FLG_CONSTTIME;
    // SAFETY: as above.
    assert_eq!(unsafe { BN_get_flags(b, !0) }, flags);
    // SAFETY: as above.
    assert_eq!(unsafe { arith::BN_add_word(b, 1) }, 0);
    // SAFETY: as above.
    assert_eq!(unsafe { BN_is_one(b) }, 1);
    // SAFETY: as above.
    unsafe { BN_free(b) };
    crate::err::take_all();
}

/// A `BN_CTX`'s numbers come back in order, zeroed, and survive `BN_free`.
#[test]
fn pool_numbers_are_reused() {
    // SAFETY: no preconditions.
    let ctx = unsafe { ctx::BN_CTX_new() };
    // SAFETY: the context made here and its numbers, here and below.
    unsafe { ctx::BN_CTX_start(ctx) };
    // SAFETY: as above.
    let a = unsafe { ctx::BN_CTX_get(ctx) };
    // SAFETY: as above.
    let b = unsafe { ctx::BN_CTX_get(ctx) };
    // SAFETY: as above.
    assert_eq!(unsafe { BN_set_word(a, 7) }, 1);
    // SAFETY: as above.
    unsafe { BN_set_flags(a, BN_FLG_CONSTTIME) };
    // SAFETY: as above.
    unsafe { BN_free(a) };
    // SAFETY: as above.
    assert_eq!(unsafe { BN_get_flags(a, BN_FLG_MALLOCED) }, 0);
    // SAFETY: as above.
    unsafe { ctx::BN_CTX_end(ctx) };
    // SAFETY: as above.
    unsafe { ctx::BN_CTX_start(ctx) };
    // SAFETY: as above.
    assert_eq!(unsafe { BN_set_word(a, 9) }, 1);
    // SAFETY: as above.
    assert_eq!(unsafe { ctx::BN_CTX_get(ctx) }, a);
    // SAFETY: as above.
    assert_eq!(unsafe { BN_is_zero(a) }, 1);
    // SAFETY: as above.
    assert_eq!(unsafe { BN_get_flags(a, BN_FLG_CONSTTIME) }, 0);
    // SAFETY: as above.
    assert_eq!(unsafe { ctx::BN_CTX_get(ctx) }, b);
    // SAFETY: as above.
    unsafe { ctx::BN_CTX_end(ctx) };
    // An end without a start does nothing.
    // SAFETY: as above.
    unsafe { ctx::BN_CTX_end(ctx) };
    // SAFETY: as above; not used afterwards.
    unsafe { ctx::BN_CTX_free(ctx) };
}

/// docs/DEVIATIONS.md: zero octets read into a negative number make zero, not OpenSSL's
/// negative zero.
#[test]
fn zero_octets_make_zero() {
    // SAFETY: no preconditions.
    let a = unsafe { BN_new() };
    // SAFETY: the number made here, here and below.
    unsafe { BN_set_word(a, 5) };
    // SAFETY: as above.
    unsafe { BN_set_negative(a, 1) };
    let zeros = [0u8; 2];
    // SAFETY: as above; two octets.
    assert_eq!(unsafe { conv::BN_bin2bn(zeros.as_ptr(), 2, a) }, a);
    // SAFETY: as above.
    assert_eq!(unsafe { BN_is_negative(a) }, 0);
    // SAFETY: as above.
    assert_eq!(unsafe { BN_is_zero(a) }, 1);
    // SAFETY: as above.
    unsafe { BN_free(a) };
}

/// docs/DEVIATIONS.md: `BN_consttime_swap` swaps whole numbers, even ones longer than `nwords`.
#[test]
fn consttime_swap_swaps_whole_numbers() {
    let (mut x, mut y) = (ptr::null_mut(), ptr::null_mut());
    // SAFETY: strings, and pointers to fill.
    unsafe { conv::BN_hex2bn(&raw mut x, c"123456789ABCDEF0123456789".as_ptr()) };
    // SAFETY: as above.
    unsafe { conv::BN_hex2bn(&raw mut y, c"-5".as_ptr()) };
    // SAFETY: the numbers made here, here and below.
    unsafe { BN_consttime_swap(1, x, y, 1) };
    // SAFETY: as above.
    assert_eq!(unsafe { BN_is_word(y, 5) }, 0);
    // SAFETY: as above.
    assert_eq!(unsafe { BN_abs_is_word(x, 5) }, 1);
    // SAFETY: as above.
    assert_eq!(unsafe { BN_is_negative(x) }, 1);
    // SAFETY: as above.
    assert_eq!(unsafe { BN_num_bits(y) }, 97);
    // SAFETY: as above.
    unsafe { BN_free(x) };
    // SAFETY: as above.
    unsafe { BN_free(y) };
}
