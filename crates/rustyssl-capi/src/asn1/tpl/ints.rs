//! Native integers as INTEGERs (`x_int64.c`, `x_long.c`): `INT32`, `UINT32`, `INT64`, and
//! `UINT64` hold a pointer to a `CRYPTO_zalloc`ed number (left out of an encoding when zero in
//! their `Z` variants), and `LONG` and `ZLONG` keep a `long` in the slot itself (left out when it
//! equals the item's size: `ASN1_LONG_UNDEF` or 0). Their item sizes are flags, not sizes.
//!
//! Decoding and printing come with `ASN1_item_d2i` and `ASN1_item_print`.

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_ITYPE_PRIMITIVE, ASN1_LONG_UNDEF, ASN1_PRIMITIVE_FUNCS, ASN1_VALUE,
    ERR_LIB_ASN1, V_ASN1_INTEGER,
};
use rustyssl_asn1::text::integer_content;

use super::{Item, PrimitiveFuncs, Pval, item, item_fns};
use crate::ffi::ffi_callback;
use crate::mem;

/// In an `INTxx` item's size: a zero value is left out.
const FLAG_ZERO_DEFAULT: c_long = 1 << 0;
/// In an `INTxx` item's size: the number is signed.
const FLAG_SIGNED: c_long = 1 << 1;

/// The item's size, its flags.
///
/// # Safety
/// `it` is a live item.
unsafe fn size(it: *const ASN1_ITEM) -> c_long {
    // SAFETY: the caller's guarantee.
    unsafe { (*it).size }
}

/// `ossl_i2c_uint64_int`: the content octets of the INTEGER with magnitude `r`, written to
/// `cont` if not NULL. Returns their length.
///
/// # Safety
/// `cont` is NULL or has room for the content.
unsafe fn i2c_uint64(cont: *mut c_uchar, r: u64, neg: bool) -> c_int {
    let bytes = r.to_be_bytes();
    let first = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    let content = integer_content(bytes.get(first..).unwrap_or(&[0]), neg);
    if !cont.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { ptr::copy_nonoverlapping(content.as_ptr(), cont, content.len()) };
    }
    c_int::try_from(content.len()).unwrap_or(c_int::MAX)
}

/// Allocates a zeroed number of `size` octets into `*pval`.
///
/// # Safety
/// `pval` is valid for a write.
unsafe fn number_new(pval: Pval, size: usize) -> c_int {
    let block = mem::alloc_zeroed(size);
    // SAFETY: the caller's guarantee.
    unsafe { pval.write(block.cast()) };
    c_int::from(!block.is_null())
}

ffi_callback! {
    /// `uint64_new`.
    ///
    /// # Safety
    /// `pval` is valid for a write.
    pub(crate) unsafe extern "C" fn uint64_new(pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { number_new(pval, size_of::<u64>()) }
    }
}

ffi_callback! {
    /// `uint32_new`.
    ///
    /// # Safety
    /// `pval` is valid for a write.
    pub(crate) unsafe extern "C" fn uint32_new(pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { number_new(pval, size_of::<u32>()) }
    }
}

ffi_callback! {
    /// `uint64_free` and `uint32_free`: frees the number and clears the slot.
    ///
    /// # Safety
    /// `pval` holds NULL or a number from this allocator.
    pub(crate) unsafe extern "C" fn number_free(pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let block = unsafe { pval.read() };
        // SAFETY: as above.
        unsafe { mem::release(block.cast()) };
        // SAFETY: as above.
        unsafe { pval.write(ptr::null_mut()) };
    }
}

ffi_callback! {
    /// `uint64_clear`: zeroes the number.
    ///
    /// # Safety
    /// `pval` holds a number of 8 octets.
    pub(crate) unsafe extern "C" fn uint64_clear(pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let number = unsafe { pval.read() };
        // SAFETY: as above.
        unsafe { number.cast::<u64>().write_unaligned(0) };
    }
}

ffi_callback! {
    /// `uint32_clear`: zeroes the number.
    ///
    /// # Safety
    /// `pval` holds a number of 4 octets.
    pub(crate) unsafe extern "C" fn uint32_clear(pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let number = unsafe { pval.read() };
        // SAFETY: as above.
        unsafe { number.cast::<u32>().write_unaligned(0) };
    }
}

ffi_callback! {
    /// `uint64_i2c`: the number's content octets, or -1 to leave out a zero by default.
    ///
    /// # Safety
    /// `pval` holds a number of 8 octets; `cont` is NULL or has room.
    pub(crate) unsafe extern "C" fn uint64_i2c(pval: *mut *const ASN1_VALUE, cont: *mut c_uchar, _putype: *mut c_int, it: *const ASN1_ITEM) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let number = unsafe { pval.read() };
        // SAFETY: as above.
        let mut utmp = unsafe { number.cast::<u64>().read_unaligned() };
        // SAFETY: as above.
        let flags = unsafe { size(it) };
        if flags & FLAG_ZERO_DEFAULT != 0 && utmp == 0 {
            return -1;
        }
        let mut neg = false;
        if flags & FLAG_SIGNED != 0 && utmp.cast_signed() < 0 {
            utmp = utmp.wrapping_neg();
            neg = true;
        }
        // SAFETY: the caller's guarantee.
        unsafe { i2c_uint64(cont, utmp, neg) }
    }
}

ffi_callback! {
    /// `uint32_i2c`: the number's content octets, or -1 to leave out a zero by default.
    ///
    /// # Safety
    /// `pval` holds a number of 4 octets; `cont` is NULL or has room.
    pub(crate) unsafe extern "C" fn uint32_i2c(pval: *mut *const ASN1_VALUE, cont: *mut c_uchar, _putype: *mut c_int, it: *const ASN1_ITEM) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let number = unsafe { pval.read() };
        // SAFETY: as above.
        let mut utmp = unsafe { number.cast::<u32>().read_unaligned() };
        // SAFETY: as above.
        let flags = unsafe { size(it) };
        if flags & FLAG_ZERO_DEFAULT != 0 && utmp == 0 {
            return -1;
        }
        let mut neg = false;
        if flags & FLAG_SIGNED != 0 && utmp.cast_signed() < 0 {
            utmp = utmp.wrapping_neg();
            neg = true;
        }
        // SAFETY: the caller's guarantee.
        unsafe { i2c_uint64(cont, u64::from(utmp), neg) }
    }
}

ffi_callback! {
    /// `long_new` and `long_free`: the item's size, in the slot.
    ///
    /// # Safety
    /// `pval` is valid for a write; `it` is a live item.
    pub(crate) unsafe extern "C" fn long_set(pval: *mut *mut ASN1_VALUE, it: *const ASN1_ITEM)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let value = unsafe { size(it) };
        // SAFETY: a `long` fits the slot, a pointer, on every target.
        unsafe { pval.cast::<c_long>().write_unaligned(value) };
    }
}

ffi_callback! {
    /// `long_new`.
    ///
    /// # Safety
    /// As for `long_set`.
    pub(crate) unsafe extern "C" fn long_new(pval: *mut *mut ASN1_VALUE, it: *const ASN1_ITEM) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { long_set(pval, it) };
        1
    }
}

ffi_callback! {
    /// `long_i2c`: the `long` in the slot as content octets, or -1 if it is the item's size.
    ///
    /// # Safety
    /// `pval` holds a `long`; `cont` is NULL or has room.
    pub(crate) unsafe extern "C" fn long_i2c(pval: *mut *const ASN1_VALUE, cont: *mut c_uchar, _putype: *mut c_int, it: *const ASN1_ITEM) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let ltmp = unsafe { pval.cast::<c_long>().read_unaligned() };
        // SAFETY: as above.
        if ltmp == unsafe { size(it) } {
            return -1;
        }
        // Negative values are complemented (one less than their magnitude), so the octets
        // are written complemented and the pad octet comes out right.
        let (sign, utmp): (u8, u64) = if ltmp < 0 { (0xff, (!ltmp).cast_unsigned()) } else { (0, ltmp.cast_unsigned()) };
        let bits = u64::BITS.wrapping_sub(utmp.leading_zeros());
        let pad = usize::from(bits % 8 == 0);
        let clen = usize::try_from(bits.wrapping_add(7) / 8).unwrap_or(0);
        if !cont.is_null() {
            let octets = utmp.to_be_bytes();
            let start = octets.len().wrapping_sub(clen);
            let mut content: Vec<u8> = Vec::with_capacity(clen.wrapping_add(pad));
            if pad == 1 {
                content.push(sign);
            }
            content.extend(octets.iter().skip(start).map(|&b| b ^ sign));
            // SAFETY: the caller's guarantee.
            unsafe { ptr::copy_nonoverlapping(content.as_ptr(), cont, content.len()) };
        }
        c_int::try_from(clen.wrapping_add(pad)).unwrap_or(c_int::MAX)
    }
}

/// `uint32_pf`.
static UINT32_PF: PrimitiveFuncs = PrimitiveFuncs(ASN1_PRIMITIVE_FUNCS {
    app_data: ptr::null_mut(),
    flags: 0,
    prim_new: Some(uint32_new),
    prim_free: Some(number_free),
    prim_clear: Some(uint32_clear),
    prim_c2i: None,
    prim_i2c: Some(uint32_i2c),
    prim_print: None,
});

/// `uint64_pf`.
static UINT64_PF: PrimitiveFuncs = PrimitiveFuncs(ASN1_PRIMITIVE_FUNCS {
    app_data: ptr::null_mut(),
    flags: 0,
    prim_new: Some(uint64_new),
    prim_free: Some(number_free),
    prim_clear: Some(uint64_clear),
    prim_c2i: None,
    prim_i2c: Some(uint64_i2c),
    prim_print: None,
});

/// `long_pf`: clearing sets the initial value, as freeing does.
static LONG_PF: PrimitiveFuncs = PrimitiveFuncs(ASN1_PRIMITIVE_FUNCS {
    app_data: ptr::null_mut(),
    flags: 0,
    prim_new: Some(long_new),
    prim_free: Some(long_set),
    prim_clear: Some(long_set),
    prim_c2i: None,
    prim_i2c: Some(long_i2c),
    prim_print: None,
});

/// An INTEGER item with functions `pf` and flags (or default) `size`.
const fn integer(
    pf: &'static PrimitiveFuncs,
    size: c_long,
    sname: &'static core::ffi::CStr,
) -> Item {
    let funcs: *const c_void = (&raw const pf.0).cast();
    item(
        ASN1_ITYPE_PRIMITIVE,
        V_ASN1_INTEGER,
        ptr::null(),
        0,
        funcs,
        size,
        sname,
    )
}

item_fns! {
    /// An `int32_t` as an INTEGER.
    pub unsafe extern "C" fn INT32_it = integer(&UINT32_PF, FLAG_SIGNED, c"INT32");
    /// A `uint32_t` as an INTEGER.
    pub unsafe extern "C" fn UINT32_it = integer(&UINT32_PF, 0, c"UINT32");
    /// An `int64_t` as an INTEGER.
    pub unsafe extern "C" fn INT64_it = integer(&UINT64_PF, FLAG_SIGNED, c"INT64");
    /// A `uint64_t` as an INTEGER.
    pub unsafe extern "C" fn UINT64_it = integer(&UINT64_PF, 0, c"UINT64");
    /// An `int32_t`, left out when zero.
    pub unsafe extern "C" fn ZINT32_it = integer(&UINT32_PF, FLAG_ZERO_DEFAULT | FLAG_SIGNED, c"ZINT32");
    /// A `uint32_t`, left out when zero.
    pub unsafe extern "C" fn ZUINT32_it = integer(&UINT32_PF, FLAG_ZERO_DEFAULT, c"ZUINT32");
    /// An `int64_t`, left out when zero.
    pub unsafe extern "C" fn ZINT64_it = integer(&UINT64_PF, FLAG_ZERO_DEFAULT | FLAG_SIGNED, c"ZINT64");
    /// A `uint64_t`, left out when zero.
    pub unsafe extern "C" fn ZUINT64_it = integer(&UINT64_PF, FLAG_ZERO_DEFAULT, c"ZUINT64");
    /// A `long` in the slot itself, left out when `ASN1_LONG_UNDEF`.
    pub unsafe extern "C" fn LONG_it = integer(&LONG_PF, ASN1_LONG_UNDEF, c"LONG");
    /// A `long` in the slot itself, left out when zero.
    pub unsafe extern "C" fn ZLONG_it = integer(&LONG_PF, 0, c"ZLONG");
}
