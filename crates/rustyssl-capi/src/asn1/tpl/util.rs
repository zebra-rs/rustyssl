//! Copying, packing, and wrapping values through their items (`ASN1_item_dup(3)`, `ASN1_dup`,
//! the time types' `_dup` functions, `ASN1_item_pack(3)`/`ASN1_item_unpack`,
//! `ASN1_TYPE_pack_sequence(3)`/`ASN1_TYPE_unpack_sequence`, and
//! `ASN1_TYPE_set_int_octetstring(3)`/`ASN1_TYPE_get_int_octetstring`), as OpenSSL's
//! `a_dup.c`, `asn_pack.c`, `a_type.c`, and `evp_asn1.c` do: each encodes, then decodes.

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASN1_GENERALIZEDTIME, ASN1_ITEM, ASN1_ITYPE_CHOICE, ASN1_ITYPE_NDEF_SEQUENCE,
    ASN1_ITYPE_SEQUENCE, ASN1_OP_DUP_POST, ASN1_OP_DUP_PRE, ASN1_OP_GET0_LIBCTX,
    ASN1_OP_GET0_PROPQ, ASN1_R_AUX_ERROR, ASN1_R_DATA_IS_WRONG, ASN1_R_DECODE_ERROR,
    ASN1_R_ENCODE_ERROR, ASN1_STRING, ASN1_TEMPLATE, ASN1_TFLG_EMBED, ASN1_TIME, ASN1_TYPE,
    ASN1_UTCTIME, ASN1_VALUE, ERR_LIB_ASN1, ERR_R_ASN1_LIB, ERR_R_PASSED_NULL_PARAMETER,
    OSSL_LIB_CTX, V_ASN1_OCTET_STRING, V_ASN1_SEQUENCE, d2i_of_void, i2d_of_void,
};

use super::decode::ASN1_item_d2i_ex;
use super::encode::ASN1_item_i2d;
use super::free::ASN1_item_free;
use super::ints::INT32_it;
use super::items::{
    ASN1_ANY_it, ASN1_GENERALIZEDTIME_it, ASN1_OCTET_STRING_it, ASN1_TIME_it, ASN1_UTCTIME_it,
};
use super::new::{ASN1_item_new, aux_callback};
use super::{Item, item, itype, size_of_long};
use crate::asn1::{any, string};
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;

ffi_export! {
    /// A copy of `x` made by encoding it with `i2d` and decoding that with `d2i`, or NULL.
    ///
    /// # Safety
    /// `i2d` and `d2i` are trusted functions for `x`'s type; `x` is NULL or a value of it.
    pub unsafe extern "C" fn ASN1_dup(i2d: i2d_of_void, d2i: d2i_of_void, x: *const c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        let (Some(i2d), Some(d2i)) = (i2d, d2i) else {
            return ptr::null_mut();
        };
        if x.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's function, measuring.
        let i = unsafe { i2d(x, ptr::null_mut()) };
        let Ok(size) = usize::try_from(i) else {
            return ptr::null_mut();
        };
        if size == 0 {
            return ptr::null_mut();
        }
        // OpenSSL's 10 octets of slack, for functions that write a little more.
        let b: *mut c_uchar = mem::alloc(size.saturating_add(10)).cast();
        if b.is_null() {
            return ptr::null_mut();
        }
        let mut p = b;
        // SAFETY: the caller's function, writing what it measured.
        let i = unsafe { i2d(x, &raw mut p) };
        let mut p2 = b.cast_const();
        // SAFETY: the caller's function, reading what was written.
        let ret = unsafe { d2i(ptr::null_mut(), &raw mut p2, c_long::from(i)) };
        // SAFETY: the buffer, from this allocator.
        unsafe { mem::release(b.cast()) };
        ret
    }
}

ffi_export! {
    /// A copy of `x`, a value of `it`, made by encoding and decoding it, with the aux
    /// callback's `ASN1_OP_DUP_PRE`/`_POST` (and the library context it gives). NULL on
    /// failure.
    ///
    /// # Safety
    /// `it` is a live item whose tables and functions can be trusted; `x` is NULL or a live
    /// value of it.
    pub unsafe extern "C" fn ASN1_item_dup(it: *const ASN1_ITEM, x: *const c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        if x.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let kind = unsafe { itype(it) };
        let callback = if matches!(kind, ASN1_ITYPE_SEQUENCE | ASN1_ITYPE_CHOICE | ASN1_ITYPE_NDEF_SEQUENCE) {
            // SAFETY: these items' funcs are aux data.
            unsafe { aux_callback(it) }
        } else {
            None
        };
        // SAFETY: a live item.
        let sname = unsafe { (*it).sname };
        let aux_error = || {
            // SAFETY: the item's name, NULL or a string.
            let name = unsafe { super::cstr_bytes(sname) };
            let mut text = b"Type=".to_vec();
            text.extend_from_slice(name.unwrap_or(b"(null)"));
            err::raise_with_bytes(ERR_LIB_ASN1, ASN1_R_AUX_ERROR, "ASN1_item_dup", &text);
        };
        let mut libctx: *mut OSSL_LIB_CTX = ptr::null_mut();
        let mut propq: *const c_char = ptr::null();
        let mut xv: *mut ASN1_VALUE = x.cast_mut().cast();
        if let Some(cb) = callback {
            // SAFETY: the application's callback, given a local copy of the pointer.
            let ok = unsafe { cb(ASN1_OP_DUP_PRE, &raw mut xv, it, ptr::null_mut()) } != 0
                // SAFETY: as above, with a local to fill.
                && unsafe { cb(ASN1_OP_GET0_LIBCTX, &raw mut xv, it, (&raw mut libctx).cast()) } != 0
                // SAFETY: as above.
                && unsafe { cb(ASN1_OP_GET0_PROPQ, &raw mut xv, it, (&raw mut propq).cast()) } != 0;
            if !ok {
                aux_error();
                return ptr::null_mut();
            }
        }
        let mut b: *mut c_uchar = ptr::null_mut();
        // SAFETY: the caller's guarantee, with a local slot.
        let i = unsafe { ASN1_item_i2d(x.cast(), &raw mut b, it) };
        if i < 0 || b.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, "ASN1_item_dup");
            return ptr::null_mut();
        }
        let mut p = b.cast_const();
        // SAFETY: the encoding just made, of `i` octets.
        let mut ret = unsafe { ASN1_item_d2i_ex(ptr::null_mut(), &raw mut p, c_long::from(i), it, libctx, propq) };
        // SAFETY: the encoding, from this allocator.
        unsafe { mem::release(b.cast()) };
        if ret.is_null() {
            return ptr::null_mut();
        }
        if let Some(cb) = callback {
            // SAFETY: the application's callback, given the copy and the original.
            if unsafe { cb(ASN1_OP_DUP_POST, &raw mut ret, it, x.cast_mut()) } == 0 {
                // SAFETY: the copy.
                unsafe { ASN1_item_free(ret, it) };
                aux_error();
                return ptr::null_mut();
            }
        }
        ret.cast()
    }
}

ffi_export! {
    /// A copy of a Time (`ASN1_item_dup`).
    ///
    /// # Safety
    /// `t` is NULL or a live time.
    pub unsafe extern "C" fn ASN1_TIME_dup(t: *const ASN1_TIME) -> *mut ASN1_TIME
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { ASN1_TIME_it() };
        // SAFETY: the type's item; the caller's guarantee.
        unsafe { ASN1_item_dup(it, t.cast()) }.cast()
    }
}

ffi_export! {
    /// A copy of a UTCTime (`ASN1_item_dup`).
    ///
    /// # Safety
    /// `t` is NULL or a live UTCTime.
    pub unsafe extern "C" fn ASN1_UTCTIME_dup(t: *const ASN1_UTCTIME) -> *mut ASN1_UTCTIME
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { ASN1_UTCTIME_it() };
        // SAFETY: the type's item; the caller's guarantee.
        unsafe { ASN1_item_dup(it, t.cast()) }.cast()
    }
}

ffi_export! {
    /// A copy of a GeneralizedTime (`ASN1_item_dup`).
    ///
    /// # Safety
    /// `t` is NULL or a live GeneralizedTime.
    pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_dup(t: *const ASN1_GENERALIZEDTIME) -> *mut ASN1_GENERALIZEDTIME
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { ASN1_GENERALIZEDTIME_it() };
        // SAFETY: the type's item; the caller's guarantee.
        unsafe { ASN1_item_dup(it, t.cast()) }.cast()
    }
}

ffi_export! {
    /// Encodes `obj` as `it` into an OCTET STRING: `*oct` if it's there (its data replaced),
    /// else a new one (stored in `*oct` if `oct` isn't NULL). Returns it, or NULL.
    ///
    /// # Safety
    /// `obj` is a live value of `it`, a live item whose tables and functions can be trusted;
    /// `oct` is NULL or a slot holding NULL or a live string.
    pub unsafe extern "C" fn ASN1_item_pack(obj: *mut c_void, it: *const ASN1_ITEM, oct: *mut *mut ASN1_STRING) -> *mut ASN1_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let existing = if oct.is_null() { ptr::null_mut() } else { unsafe { oct.read() } };
        let octmp = if existing.is_null() {
            let s = string::type_new(V_ASN1_OCTET_STRING);
            if s.is_null() {
                err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, "ASN1_item_pack");
                return ptr::null_mut();
            }
            s
        } else {
            existing
        };
        let fail = move |reason: c_int| {
            err::raise(ERR_LIB_ASN1, reason, "ASN1_item_pack");
            if existing.is_null() {
                // SAFETY: the string made above.
                unsafe { string::ASN1_STRING_free(octmp) };
            }
            ptr::null_mut()
        };
        // SAFETY: a live string.
        unsafe { string::ASN1_STRING_set0(octmp, ptr::null_mut(), 0) };
        // SAFETY: as above.
        let s = unsafe { &mut *octmp };
        // SAFETY: the caller's guarantee; the string's data slot is NULL.
        s.length = unsafe { ASN1_item_i2d(obj.cast_const().cast(), &raw mut s.data, it) };
        if s.length <= 0 {
            return fail(ASN1_R_ENCODE_ERROR);
        }
        if s.data.is_null() {
            return fail(ERR_R_ASN1_LIB);
        }
        if !oct.is_null() && existing.is_null() {
            // SAFETY: the caller's slot.
            unsafe { oct.write(octmp) };
        }
        octmp
    }
}

/// `ASN1_item_unpack` and `_ex`: decodes `oct`'s octets as `it`.
///
/// # Safety
/// As for `ASN1_item_unpack_ex`.
unsafe fn unpack(
    oct: *const ASN1_STRING,
    it: *const ASN1_ITEM,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> *mut c_void {
    if oct.is_null() {
        err::raise(
            ERR_LIB_ASN1,
            ERR_R_PASSED_NULL_PARAMETER,
            "ASN1_item_unpack",
        );
        return ptr::null_mut();
    }
    // SAFETY: the caller's guarantee.
    let string = unsafe { &*oct };
    let (mut p, len) = (string.data.cast_const(), string.length);
    // SAFETY: a string's data holds its length.
    let ret = unsafe {
        ASN1_item_d2i_ex(
            ptr::null_mut(),
            &raw mut p,
            c_long::from(len),
            it,
            libctx,
            propq,
        )
    };
    if ret.is_null() {
        err::raise(ERR_LIB_ASN1, ASN1_R_DECODE_ERROR, "ASN1_item_unpack");
    }
    ret.cast()
}

ffi_export! {
    /// Decodes the octets of `oct` as `it`. Returns the value, or NULL
    /// (`ASN1_R_DECODE_ERROR`).
    ///
    /// Unlike OpenSSL, NULL `oct` is an error rather than a crash (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `oct` is NULL or a live string; `it` is a live item whose tables and functions can be
    /// trusted.
    pub unsafe extern "C" fn ASN1_item_unpack(oct: *const ASN1_STRING, it: *const ASN1_ITEM) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { unpack(oct, it, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// `ASN1_item_unpack`, passing `libctx` and `propq` on.
    ///
    /// # Safety
    /// As for `ASN1_item_unpack`; `propq` is NULL or a string.
    pub unsafe extern "C" fn ASN1_item_unpack_ex(oct: *const ASN1_STRING, it: *const ASN1_ITEM, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { unpack(oct, it, libctx, propq) }
    }
}

ffi_export! {
    /// Encodes `s` as `it` and stores it as a SEQUENCE in `*t` (or a new `ASN1_TYPE`, stored
    /// in `*t` if `t` isn't NULL). Returns the `ASN1_TYPE`, or NULL.
    ///
    /// # Safety
    /// `s` is a live value of `it`, a live item whose tables and functions can be trusted; `t`
    /// is NULL or a slot holding NULL or a live `ASN1_TYPE`.
    pub unsafe extern "C" fn ASN1_TYPE_pack_sequence(it: *const ASN1_ITEM, s: *mut c_void, t: *mut *mut ASN1_TYPE) -> *mut ASN1_TYPE
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let oct = unsafe { ASN1_item_pack(s, it, ptr::null_mut()) };
        if oct.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        let existing = if t.is_null() { ptr::null_mut() } else { unsafe { t.read() } };
        let rt = if existing.is_null() {
            // SAFETY: no preconditions.
            let any_it = unsafe { ASN1_ANY_it() };
            // SAFETY: the ANY item.
            let rt: *mut ASN1_TYPE = unsafe { ASN1_item_new(any_it) }.cast();
            if rt.is_null() {
                // SAFETY: the string made above.
                unsafe { string::ASN1_STRING_free(oct) };
                return ptr::null_mut();
            }
            if !t.is_null() {
                // SAFETY: the caller's slot.
                unsafe { t.write(rt) };
            }
            rt
        } else {
            existing
        };
        // SAFETY: a live ASN1_TYPE, given the string.
        unsafe { any::ASN1_TYPE_set(rt, V_ASN1_SEQUENCE, oct.cast()) };
        rt
    }
}

ffi_export! {
    /// Decodes the SEQUENCE `t` holds as `it`, or NULL if it holds none.
    ///
    /// # Safety
    /// `t` is NULL or a live `ASN1_TYPE`; `it` is a live item whose tables and functions can be
    /// trusted.
    pub unsafe extern "C" fn ASN1_TYPE_unpack_sequence(it: *const ASN1_ITEM, t: *const ASN1_TYPE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        if t.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let typ = unsafe { &*t };
        // SAFETY: the union's pointer member, read as OpenSSL reads it.
        let sequence = unsafe { typ.value.sequence };
        if typ.type_ != V_ASN1_SEQUENCE || sequence.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: a live string.
        unsafe { ASN1_item_unpack(sequence, it) }
    }
}

/// `asn1_int_oct`: SEQUENCE { INTEGER (an `int32_t`), OCTET STRING }.
#[repr(C)]
struct IntOct {
    num: i32,
    oct: *mut ASN1_STRING,
}

/// The templates of `asn1_int_oct`.
struct IntOctTemplates([ASN1_TEMPLATE; 2]);
// SAFETY: immutable tables of pointers to static data.
unsafe impl Sync for IntOctTemplates {}

static INT_OCT_TT: IntOctTemplates = IntOctTemplates([
    super::template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(IntOct, num),
        c"num",
        INT32_it,
    ),
    super::template_at(0, 0, offset_of!(IntOct, oct), c"oct", ASN1_OCTET_STRING_it),
]);

static INT_OCT: Item = item(
    ASN1_ITYPE_SEQUENCE,
    V_ASN1_SEQUENCE,
    &raw const INT_OCT_TT.0 as *const ASN1_TEMPLATE,
    2,
    ptr::null(),
    size_of_long::<IntOct>(),
    c"asn1_int_oct",
);

ffi_export! {
    /// Makes `a` a SEQUENCE of `num` (as a 32-bit INTEGER, cut to its low 32 bits as in C)
    /// and an OCTET STRING of `len` octets of `data`. Returns 1, or 0.
    ///
    /// # Safety
    /// `a` is NULL or a live `ASN1_TYPE`; `data` holds `len` octets.
    pub unsafe extern "C" fn ASN1_TYPE_set_int_octetstring(a: *mut ASN1_TYPE, num: c_long, data: *mut c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        let mut oct = ASN1_STRING { length: len, type_: V_ASN1_OCTET_STRING, data, flags: 0 };
        let mut atmp = IntOct { num: super::long_to_int(num), oct: &raw mut oct };
        let mut a = a;
        let given = !a.is_null();
        // SAFETY: a local value of the item; the caller's guarantee for `a`.
        let ret = unsafe { ASN1_TYPE_pack_sequence(&raw const INT_OCT.0, (&raw mut atmp).cast(), &raw mut a) };
        if !ret.is_null() && !given {
            // OpenSSL leaks the ASN1_TYPE it made here; it's freed instead.
            // SAFETY: no preconditions.
            let any_it = unsafe { ASN1_ANY_it() };
            // SAFETY: the ASN1_TYPE just made.
            unsafe { ASN1_item_free(ret.cast(), any_it) };
        }
        c_int::from(!ret.is_null())
    }
}

ffi_export! {
    /// Reads a SEQUENCE of an INTEGER and an OCTET STRING from `a`: the number into `*num` (if
    /// not NULL), up to `max_len` octets into `data` (if not NULL). Returns the OCTET STRING's
    /// length, or -1 (`ASN1_R_DATA_IS_WRONG`).
    ///
    /// Unlike OpenSSL, NULL `a` and a negative `max_len` don't crash (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `a` is NULL or a live `ASN1_TYPE`; `num` is NULL or valid for a write; `data` is NULL
    /// or has room for `max_len` octets.
    pub unsafe extern "C" fn ASN1_TYPE_get_int_octetstring(a: *const ASN1_TYPE, num: *mut c_long, data: *mut c_uchar, max_len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        let wrong = || {
            err::raise(ERR_LIB_ASN1, ASN1_R_DATA_IS_WRONG, "ASN1_TYPE_get_int_octetstring");
            -1
        };
        if a.is_null() {
            return wrong();
        }
        // SAFETY: the caller's guarantee.
        let typ = unsafe { &*a };
        // SAFETY: the union's pointer member.
        let sequence = unsafe { typ.value.sequence };
        if typ.type_ != V_ASN1_SEQUENCE || sequence.is_null() {
            return wrong();
        }
        // SAFETY: a live ASN1_TYPE holding a SEQUENCE.
        let atmp: *mut IntOct = unsafe { ASN1_TYPE_unpack_sequence(&raw const INT_OCT.0, a) }.cast();
        if atmp.is_null() {
            return wrong();
        }
        // SAFETY: a decoded value of the item.
        let value = unsafe { &*atmp };
        // SAFETY: its OCTET STRING.
        let octets = unsafe { &*value.oct };
        let ret = octets.length;
        if !num.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { num.write(c_long::from(value.num)) };
        }
        let n = ret.min(max_len);
        if !data.is_null()
            && let Ok(n) = usize::try_from(n)
            && n > 0
        {
            // SAFETY: the string holds `ret` octets; the caller's room for `max_len`.
            unsafe { ptr::copy_nonoverlapping(octets.data, data, n) };
        }
        // SAFETY: the decoded value.
        unsafe { ASN1_item_free(atmp.cast(), &raw const INT_OCT.0) };
        ret
    }
}

/// `asn1_oct_int`: SEQUENCE { OCTET STRING, INTEGER (an `int32_t`) }, as GCM's parameters.
#[repr(C)]
struct OctInt {
    oct: *mut ASN1_STRING,
    num: i32,
}

static OCT_INT_TT: IntOctTemplates = IntOctTemplates([
    super::template_at(0, 0, offset_of!(OctInt, oct), c"oct", ASN1_OCTET_STRING_it),
    super::template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(OctInt, num),
        c"num",
        INT32_it,
    ),
]);

static OCT_INT: Item = item(
    ASN1_ITYPE_SEQUENCE,
    V_ASN1_SEQUENCE,
    &raw const OCT_INT_TT.0 as *const ASN1_TEMPLATE,
    2,
    ptr::null(),
    size_of_long::<OctInt>(),
    c"asn1_oct_int",
);

/// `ossl_asn1_type_set_octetstring_int`: `a` made a SEQUENCE of `len` octets of `data` and
/// `num` (cut to 32 bits, as in C). Whether it worked.
///
/// # Safety
/// `a` is a live `ASN1_TYPE`; `data` holds `len` octets.
pub(crate) unsafe fn set_octetstring_int(
    a: *mut ASN1_TYPE,
    num: c_long,
    data: *mut c_uchar,
    len: c_int,
) -> bool {
    let mut oct = ASN1_STRING {
        length: len,
        type_: V_ASN1_OCTET_STRING,
        data,
        flags: 0,
    };
    let mut atmp = OctInt {
        oct: &raw mut oct,
        num: super::long_to_int(num),
    };
    let mut a = a;
    // SAFETY: a local value of the item; the caller's guarantee for `a`.
    !unsafe { ASN1_TYPE_pack_sequence(&raw const OCT_INT.0, (&raw mut atmp).cast(), &raw mut a) }
        .is_null()
}

/// `ossl_asn1_type_get_octetstring_int`: from a SEQUENCE of an OCTET STRING and an INTEGER in
/// `a`, the number into `*num` and up to `data.len()` octets into `data`. The OCTET STRING's
/// length, or -1 (`ASN1_R_DATA_IS_WRONG`).
///
/// # Safety
/// `a` is NULL or a live `ASN1_TYPE`.
pub(crate) unsafe fn get_octetstring_int(
    a: *const ASN1_TYPE,
    num: &mut c_long,
    data: &mut [u8],
) -> c_int {
    let wrong = || {
        err::raise(
            ERR_LIB_ASN1,
            ASN1_R_DATA_IS_WRONG,
            "ossl_asn1_type_get_octetstring_int",
        );
        -1
    };
    // SAFETY: the caller's guarantee.
    let Some(typ) = (unsafe { a.as_ref() }) else {
        return wrong();
    };
    // SAFETY: the union's pointer member.
    let sequence = unsafe { typ.value.sequence };
    if typ.type_ != V_ASN1_SEQUENCE || sequence.is_null() {
        return wrong();
    }
    // SAFETY: a live ASN1_TYPE holding a SEQUENCE.
    let atmp: *mut OctInt = unsafe { ASN1_TYPE_unpack_sequence(&raw const OCT_INT.0, a) }.cast();
    // SAFETY: a decoded value of the item, or NULL.
    let Some(value) = (unsafe { atmp.as_ref() }) else {
        return wrong();
    };
    // SAFETY: its OCTET STRING.
    let octets = unsafe { &*value.oct };
    let ret = octets.length;
    *num = c_long::from(value.num);
    let n = usize::try_from(ret).unwrap_or(0).min(data.len());
    if n > 0 && !octets.data.is_null() {
        // SAFETY: the string holds `ret` octets; room for `n`.
        unsafe { ptr::copy_nonoverlapping(octets.data, data.as_mut_ptr(), n) };
    }
    // SAFETY: the decoded value.
    unsafe { ASN1_item_free(atmp.cast(), &raw const OCT_INT.0) };
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_and_negative_arguments_are_safe() {
        // SAFETY: no preconditions.
        let it = unsafe { ASN1_ANY_it() };
        // SAFETY: NULL is refused.
        assert!(unsafe { ASN1_item_unpack(ptr::null(), it) }.is_null());
        // SAFETY: as above.
        let v = unsafe { ASN1_item_unpack_ex(ptr::null(), it, ptr::null_mut(), ptr::null()) };
        assert!(v.is_null());
        // SAFETY: as above.
        let got = unsafe {
            ASN1_TYPE_get_int_octetstring(ptr::null(), ptr::null_mut(), ptr::null_mut(), 0)
        };
        assert_eq!(got, -1);
        // SAFETY: a new ASN1_TYPE.
        let t: *mut ASN1_TYPE = unsafe { ASN1_item_new(it) }.cast();
        let mut data = *b"hello";
        // SAFETY: as above, with 5 octets.
        let set = unsafe { ASN1_TYPE_set_int_octetstring(t, 1, data.as_mut_ptr(), 5) };
        assert_eq!(set, 1);
        let mut out = [0u8; 4];
        // SAFETY: a negative length copies nothing.
        let got =
            unsafe { ASN1_TYPE_get_int_octetstring(t, ptr::null_mut(), out.as_mut_ptr(), -1) };
        assert_eq!((got, out), (5, [0; 4]));
        // SAFETY: as above.
        unsafe { ASN1_item_free(t.cast(), it) };
        // SAFETY: no preconditions.
        unsafe { err::ERR_clear_error() };
    }
}

/// `ossl_asn1_item_digest_ex`: the digest of `asn`'s encoding (with the digest fetched in the
/// library context when it isn't a provider's): 1, or 0.
///
/// # Safety
/// `it` is a live item; `md` is a live digest; `asn` is a value of `it`; `data` has room for
/// the digest; `len` is NULL or writable; `libctx` is NULL or live; `propq` is NULL or a
/// string.
pub(crate) unsafe fn item_digest_ex(
    it: *const ASN1_ITEM,
    md: *const rustyssl_abi::EVP_MD,
    asn: *mut c_void,
    data: *mut c_uchar,
    len: *mut core::ffi::c_uint,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> c_int {
    let mut s: *mut c_uchar = ptr::null_mut();
    // SAFETY: the caller's value and item; a place for the encoding.
    let i = unsafe { ASN1_item_i2d(asn.cast(), &raw mut s, it) };
    if i < 0 || s.is_null() {
        return 0;
    }
    let mut fetched = md.cast_mut();
    // SAFETY: the caller's digest.
    if unsafe { crate::evp::digest::EVP_MD_get0_provider(md) }.is_null() {
        // No engines: the digest is fetched by its name.
        // SAFETY: the caller's digest.
        let name = unsafe { crate::evp::digest::EVP_MD_get0_name(md) };
        // SAFETY: the caller's library context and properties; the digest's name.
        fetched = unsafe { crate::evp::digest::EVP_MD_fetch(libctx, name, propq) };
    }
    let ret = if fetched.is_null() {
        0
    } else {
        // SAFETY: the encoding (`i` octets); the caller's room.
        unsafe {
            crate::evp::md_ctx::EVP_Digest(
                s.cast(),
                usize::try_from(i).unwrap_or(0),
                data,
                len,
                fetched,
                ptr::null_mut(),
            )
        }
    };
    // SAFETY: the encoding made above.
    unsafe { mem::release(s.cast()) };
    if !ptr::eq(fetched, md) {
        // SAFETY: fetched above.
        unsafe { crate::evp::digest::EVP_MD_free(fetched) };
    }
    ret
}

ffi_export! {
    /// The digest of `asn`'s encoding into `data` (its length into `*len`): 1, or 0.
    ///
    /// # Safety
    /// `it` is a live item; `md` is a live digest; `asn` is a value of `it`; `data` has room
    /// for the digest; `len` is NULL or writable.
    pub unsafe extern "C" fn ASN1_item_digest(it: *const ASN1_ITEM, md: *const rustyssl_abi::EVP_MD, asn: *mut c_void, data: *mut c_uchar, len: *mut core::ffi::c_uint) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { item_digest_ex(it, md, asn, data, len, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// The digest of what `i2d` encodes `data` to: 1, or 0 (`ERR_R_INTERNAL_ERROR` for an
    /// empty or failed encoding).
    ///
    /// # Safety
    /// `i2d` is a trusted encoder of `data`'s type; `type_` is a live digest; `md` has room for
    /// the digest; `len` is NULL or writable.
    pub unsafe extern "C" fn ASN1_digest(i2d: i2d_of_void, type_: *const rustyssl_abi::EVP_MD, data: *mut c_char, md: *mut c_uchar, len: *mut core::ffi::c_uint) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        let Some(i2d) = i2d else { return 0 };
        // SAFETY: the caller's encoder and value.
        let inl = unsafe { i2d(data.cast(), ptr::null_mut()) };
        if inl <= 0 {
            err::raise(ERR_LIB_ASN1, rustyssl_abi::ERR_R_INTERNAL_ERROR, "ASN1_digest");
            return 0;
        }
        let ul = usize::try_from(inl).unwrap_or(0);
        let s: *mut c_uchar = mem::alloc(ul).cast();
        if s.is_null() {
            return 0;
        }
        let mut p = s;
        // SAFETY: as above; room for the encoding.
        unsafe { i2d(data.cast(), &raw mut p) };
        // SAFETY: the encoding; the caller's room.
        let ok = unsafe { crate::evp::md_ctx::EVP_Digest(s.cast(), ul, md, len, type_, ptr::null_mut()) } != 0;
        // SAFETY: made above.
        unsafe { mem::release(s.cast()) };
        c_int::from(ok)
    }
}
