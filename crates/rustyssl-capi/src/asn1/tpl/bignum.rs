//! `BIGNUM_it` and `CBIGNUM_it` (`x_bignum.c`): a `BIGNUM` as an INTEGER. The content is the
//! number's magnitude: a negative number encodes as its absolute value, and a negative
//! INTEGER decodes as its octets read unsigned, as OpenSSL's do. `CBIGNUM`'s numbers are
//! secure-heap ones, constant-time, and cleared when freed.

use core::ffi::{c_char, c_int, c_long, c_uchar};
use core::ptr;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_ITYPE_PRIMITIVE, ASN1_PCTX, ASN1_PRIMITIVE_FUNCS, ASN1_VALUE, BIGNUM, BIO,
    BN_FLG_CONSTTIME, ERR_LIB_ASN1, V_ASN1_INTEGER,
};

use super::{Item, PrimitiveFuncs, item, item_fns};
use crate::bio::BIO_puts;
use crate::bn::conv::{BN_bin2bn, BN_bn2bin, BN_print};
use crate::bn::{BN_clear_free, BN_free, BN_new, BN_num_bits, BN_secure_new, BN_set_flags};
use crate::ffi::ffi_callback;

/// `BN_SENSITIVE`, `x_bignum.c`'s flag in the item's size: the numbers are cleared when freed.
const BN_SENSITIVE: c_long = 1;

ffi_callback! {
    /// `bn_new`.
    ///
    /// # Safety
    /// `pval` is a writable slot.
    pub(crate) unsafe extern "C" fn bn_new(pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let b = unsafe { BN_new() };
        // SAFETY: the caller's guarantee.
        unsafe { pval.write(b.cast()) };
        c_int::from(!b.is_null())
    }
}

ffi_callback! {
    /// `bn_secure_new`.
    ///
    /// # Safety
    /// `pval` is a writable slot.
    pub(crate) unsafe extern "C" fn bn_secure_new(pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let b = unsafe { BN_secure_new() };
        // SAFETY: the caller's guarantee.
        unsafe { pval.write(b.cast()) };
        c_int::from(!b.is_null())
    }
}

ffi_callback! {
    /// `bn_free`: cleared first for a sensitive item.
    ///
    /// # Safety
    /// `pval` holds NULL or a live `BIGNUM`; `it` is one of this module's items.
    pub(crate) unsafe extern "C" fn bn_free(pval: *mut *mut ASN1_VALUE, it: *const ASN1_ITEM)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let b: *mut BIGNUM = unsafe { pval.read() }.cast();
        if b.is_null() {
            return;
        }
        // SAFETY: as above.
        if unsafe { (*it).size } & BN_SENSITIVE != 0 {
            // SAFETY: as above; freed once.
            unsafe { BN_clear_free(b) };
        } else {
            // SAFETY: as above.
            unsafe { BN_free(b) };
        }
        // SAFETY: as above.
        unsafe { pval.write(ptr::null_mut()) };
    }
}

ffi_callback! {
    /// `bn_i2c`: the magnitude, with a zero octet first when its top bit is set (and for zero).
    ///
    /// # Safety
    /// `pval` holds NULL or a live `BIGNUM`; `cont` is NULL or has room for the content.
    pub(crate) unsafe extern "C" fn bn_i2c(pval: *mut *const ASN1_VALUE, cont: *mut c_uchar, _putype: *mut c_int, _it: *const ASN1_ITEM) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let b: *const BIGNUM = unsafe { pval.read() }.cast();
        if b.is_null() {
            return -1;
        }
        // SAFETY: a live number.
        let bits = unsafe { BN_num_bits(b) };
        let pad = c_int::from(bits & 7 == 0);
        let bytes = (bits + 7) / 8;
        if !cont.is_null() {
            let mut at = cont;
            if pad == 1 {
                // SAFETY: the caller's room for the content, a zero octet first.
                unsafe { at.write(0) };
                at = at.wrapping_add(1);
            }
            // SAFETY: as above, for the number's octets after it.
            unsafe { BN_bn2bin(b, at) };
        }
        pad + bytes
    }
}

/// `bn_c2i` into the slot, making a number with `make` when it's empty.
///
/// # Safety
/// `pval` holds NULL or a live `BIGNUM`; `cont` has `len` octets.
unsafe fn c2i(
    pval: *mut *mut ASN1_VALUE,
    cont: *const c_uchar,
    len: c_int,
    make: unsafe extern "C" fn(*mut *mut ASN1_VALUE, *const ASN1_ITEM) -> c_int,
    it: *const ASN1_ITEM,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let made = unsafe { pval.read() }.is_null();
    // SAFETY: as above.
    if made && unsafe { make(pval, it) } == 0 {
        return 0;
    }
    // SAFETY: as above.
    let b: *mut BIGNUM = unsafe { pval.read() }.cast();
    // SAFETY: the content and its length; a live number to hold it.
    if unsafe { BN_bin2bn(cont, len, b) }.is_null() {
        // OpenSSL frees the number here even when it was the caller's, which can only happen
        // when memory runs out; a number the slot already held is left to its owner.
        if made {
            // SAFETY: the number just made.
            unsafe { bn_free(pval, it) };
        }
        return 0;
    }
    1
}

ffi_callback! {
    /// `bn_c2i`: the content's octets, unsigned, into the slot's number or a new one.
    ///
    /// # Safety
    /// `pval` holds NULL or a live `BIGNUM`; `cont` has `len` octets.
    pub(crate) unsafe extern "C" fn bn_c2i(pval: *mut *mut ASN1_VALUE, cont: *const c_uchar, len: c_int, _utype: c_int, _free_cont: *mut c_char, it: *const ASN1_ITEM) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { c2i(pval, cont, len, bn_new, it) }
    }
}

ffi_callback! {
    /// `bn_secure_c2i`: as `bn_c2i`, into a secure number, then constant-time.
    ///
    /// # Safety
    /// `pval` holds NULL or a live `BIGNUM`; `cont` has `len` octets.
    pub(crate) unsafe extern "C" fn bn_secure_c2i(pval: *mut *mut ASN1_VALUE, cont: *const c_uchar, len: c_int, _utype: c_int, _free_cont: *mut c_char, it: *const ASN1_ITEM) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        if unsafe { c2i(pval, cont, len, bn_secure_new, it) } == 0 {
            return 0;
        }
        // SAFETY: the number decoded.
        let b: *mut BIGNUM = unsafe { pval.read() }.cast();
        // SAFETY: as above.
        unsafe { BN_set_flags(b, BN_FLG_CONSTTIME) };
        1
    }
}

ffi_callback! {
    /// `bn_print`: `BN_print`'s hexadecimal and a newline.
    ///
    /// # Safety
    /// `out` is NULL or a live BIO; `pval` holds a live `BIGNUM`.
    pub(crate) unsafe extern "C" fn bn_print(out: *mut BIO, pval: *mut *const ASN1_VALUE, _it: *const ASN1_ITEM, _indent: c_int, _pctx: *const ASN1_PCTX) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let b: *const BIGNUM = unsafe { pval.read() }.cast();
        // SAFETY: as above.
        if unsafe { BN_print(out, b) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        c_int::from(unsafe { BIO_puts(out, c"\n".as_ptr()) } > 0)
    }
}

/// `bignum_pf`.
static BIGNUM_PF: PrimitiveFuncs = PrimitiveFuncs(ASN1_PRIMITIVE_FUNCS {
    app_data: ptr::null_mut(),
    flags: 0,
    prim_new: Some(bn_new),
    prim_free: Some(bn_free),
    prim_clear: None,
    prim_c2i: Some(bn_c2i),
    prim_i2c: Some(bn_i2c),
    prim_print: Some(bn_print),
});

/// `cbignum_pf`.
static CBIGNUM_PF: PrimitiveFuncs = PrimitiveFuncs(ASN1_PRIMITIVE_FUNCS {
    app_data: ptr::null_mut(),
    flags: 0,
    prim_new: Some(bn_secure_new),
    prim_free: Some(bn_free),
    prim_clear: None,
    prim_c2i: Some(bn_secure_c2i),
    prim_i2c: Some(bn_i2c),
    prim_print: Some(bn_print),
});

/// An INTEGER item over `BIGNUM`s with functions `pf` and flags `size`.
const fn bignum(
    pf: &'static PrimitiveFuncs,
    size: c_long,
    sname: &'static core::ffi::CStr,
) -> Item {
    item(
        ASN1_ITYPE_PRIMITIVE,
        V_ASN1_INTEGER,
        ptr::null(),
        0,
        (&raw const pf.0).cast(),
        size,
        sname,
    )
}

item_fns! {
    /// A `BIGNUM` as an INTEGER.
    pub unsafe extern "C" fn BIGNUM_it = bignum(&BIGNUM_PF, 0, c"BIGNUM");
    /// A secret `BIGNUM` as an INTEGER: secure heap, constant-time, cleared when freed.
    pub unsafe extern "C" fn CBIGNUM_it = bignum(&CBIGNUM_PF, BN_SENSITIVE, c"CBIGNUM");
}
