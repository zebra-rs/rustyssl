//! Extern items over opaque handles that OpenSSL describes as SEQUENCEs of the handle's own
//! fields (`RSAPrivateKey` over an `RSA`, for example). rustyssl's handles have no C layout to
//! put templates over, so each such item is `ASN1_ITYPE_EXTERN` (as the architecture has it for
//! built-in opaque types) and goes through a *shadow*: a private C structure with the fields
//! OpenSSL's templates name, described by a private SEQUENCE item with OpenSSL's field and type
//! names. Decoding fills a shadow (whose fields start as the handle's own numbers, so they're
//! reused as OpenSSL reuses them) and moves it into the handle; encoding and printing lend the
//! handle's fields to a shadow and walk it. The engine does the work, so the encodings, the
//! errors (`Field=n, Type=RSAPrivateKey`), and the printed text are OpenSSL's.
//!
//! What differs is what an application could see of the item itself: its `itype` is
//! `ASN1_ITYPE_EXTERN`, not `ASN1_ITYPE_SEQUENCE`, and a decode inside it starts a new count of
//! the nesting limit, as OpenSSL's own extern items (`X509_NAME`) do.

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{ASN1_EXTERN_FUNCS, ASN1_ITEM, ASN1_TLC, ASN1_VALUE, ERR_LIB_ASN1};

use super::decode::ASN1_item_ex_d2i;
use super::encode::ASN1_item_ex_i2d;
use super::free::ASN1_item_ex_free;
use crate::ffi::ffi_callback;

/// What a shadow is lent for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lend {
    /// Decoding into: the handle's numbers that a decode reuses.
    Decode,
    /// Encoding or printing: everything the encoding holds.
    Encode,
}

/// A shadowed item's functions. `funcs` is first, so the item's `funcs` pointer is this
/// structure's; its `app_data` is [`MARK`]'s address, which says the rest follows.
#[repr(C)]
pub(crate) struct Shadowed {
    pub(crate) funcs: ASN1_EXTERN_FUNCS,
    /// The private SEQUENCE item over the shadow structure.
    pub(crate) item: unsafe extern "C" fn() -> *const ASN1_ITEM,
    /// A new, empty handle, or NULL with the error raised.
    pub(crate) new: unsafe fn() -> *mut ASN1_VALUE,
    /// Drops a reference to a handle.
    pub(crate) free: unsafe fn(*mut ASN1_VALUE),
    /// A shadow lending the handle's fields (an empty one for NULL), or NULL when memory runs
    /// out. The engine frees it as a value of `item` without the lent fields; [`Self::release`]
    /// frees only the shadow's own memory.
    pub(crate) lend: unsafe fn(*const ASN1_VALUE, Lend) -> *mut ASN1_VALUE,
    /// Moves a decoded shadow's fields into the handle, which then owns them.
    pub(crate) commit: unsafe fn(*mut ASN1_VALUE, *mut ASN1_VALUE),
    /// Frees a shadow's own memory, never its fields' values.
    pub(crate) release: unsafe fn(*mut ASN1_VALUE),
}

// SAFETY: immutable, with no pointers but functions and the mark.
unsafe impl Sync for Shadowed {}

/// The mark in a shadowed item's `app_data`.
pub(crate) static MARK: u8 = 0;

/// The extern functions of a shadowed item, with [`MARK`].
pub(crate) const FUNCS: ASN1_EXTERN_FUNCS = ASN1_EXTERN_FUNCS {
    app_data: (&raw const MARK).cast_mut().cast(),
    asn1_ex_new: Some(ex_new),
    asn1_ex_free: Some(ex_free),
    asn1_ex_clear: None,
    asn1_ex_d2i: Some(ex_d2i),
    asn1_ex_i2d: Some(ex_i2d),
    asn1_ex_print: None,
    asn1_ex_new_ex: None,
    asn1_ex_d2i_ex: None,
};

/// The shadowed functions of an item, if it is one of rustyssl's shadowed items.
///
/// # Safety
/// `it` is a live item whose tables can be trusted.
pub(crate) unsafe fn shadowed(it: *const ASN1_ITEM) -> Option<&'static Shadowed> {
    // SAFETY: the caller's guarantee.
    let funcs = unsafe { (*it).funcs };
    if funcs.is_null() {
        return None;
    }
    // SAFETY: an extern item's funcs start with `ASN1_EXTERN_FUNCS`, whose first field is
    // `app_data`.
    let app_data = unsafe { funcs.cast::<*mut c_void>().read() };
    if !ptr::eq(app_data.cast_const().cast::<u8>(), &raw const MARK) {
        return None;
    }
    // SAFETY: only `Shadowed` statics carry the mark.
    Some(unsafe { &*funcs.cast::<Shadowed>() })
}

/// The shadowed functions of one of this module's items.
///
/// # Safety
/// `it` is a shadowed item (its functions were called through it).
unsafe fn own(it: *const ASN1_ITEM) -> Option<&'static Shadowed> {
    // SAFETY: the caller's guarantee.
    unsafe { shadowed(it) }
}

ffi_callback! {
    /// A new handle in the slot.
    ///
    /// # Safety
    /// `pval` is a writable slot; `it` is a shadowed item.
    pub(crate) unsafe extern "C" fn ex_new(pval: *mut *mut ASN1_VALUE, it: *const ASN1_ITEM) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let Some(sh) = (unsafe { own(it) }) else { return 0 };
        // SAFETY: the item's own function.
        let h = unsafe { (sh.new)() };
        // SAFETY: the caller's guarantee.
        unsafe { pval.write(h) };
        c_int::from(!h.is_null())
    }
}

ffi_callback! {
    /// Drops the slot's handle and empties the slot.
    ///
    /// # Safety
    /// `pval` holds NULL or a live handle of the item; `it` is a shadowed item.
    pub(crate) unsafe extern "C" fn ex_free(pval: *mut *mut ASN1_VALUE, it: *const ASN1_ITEM)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let h = unsafe { pval.read() };
        // SAFETY: as above.
        if let (false, Some(sh)) = (h.is_null(), unsafe { own(it) }) {
            // SAFETY: the slot's reference.
            unsafe { (sh.free)(h) };
        }
        // SAFETY: as above.
        unsafe { pval.write(ptr::null_mut()) };
    }
}

ffi_callback! {
    /// Decodes into a shadow lending the slot's handle, then moves it into the handle (a new
    /// one when the slot is empty). A failure leaves the handle's numbers as the decode left
    /// them (as OpenSSL's, which decodes into them); the engine then frees the handle.
    ///
    /// # Safety
    /// As for `ASN1_item_ex_d2i`, with `pval` holding NULL or a live handle of the item.
    pub(crate) unsafe extern "C" fn ex_d2i(pval: *mut *mut ASN1_VALUE, in_: *mut *const c_uchar, len: c_long, it: *const ASN1_ITEM, tag: c_int, aclass: c_int, opt: c_char, ctx: *mut ASN1_TLC) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let Some(sh) = (unsafe { own(it) }) else { return 0 };
        // SAFETY: as above.
        let h = unsafe { pval.read() };
        // SAFETY: NULL or a live handle.
        let mut shadow = unsafe { (sh.lend)(h, Lend::Decode) };
        if shadow.is_null() {
            return 0;
        }
        // SAFETY: the item's own shadow item.
        let sit = unsafe { (sh.item)() };
        // SAFETY: the caller's input, decoded into the shadow; on failure the engine frees the
        // shadow, its aux callback keeping the lent numbers.
        let ret = unsafe { ASN1_item_ex_d2i(&raw mut shadow, in_, len, sit, tag, aclass, opt, ctx) };
        if ret <= 0 {
            return ret;
        }
        let h = if h.is_null() {
            // SAFETY: the item's own function.
            let h = unsafe { (sh.new)() };
            if h.is_null() {
                // SAFETY: the decoded shadow, nothing of it lent.
                unsafe { ASN1_item_ex_free(&raw mut shadow, sit) };
                return 0;
            }
            // SAFETY: the caller's slot.
            unsafe { pval.write(h) };
            h
        } else {
            h
        };
        // SAFETY: a live handle and the shadow decoded for it, whose numbers it takes.
        unsafe { (sh.commit)(h, shadow) };
        // SAFETY: the shadow's own memory, its numbers now the handle's.
        unsafe { (sh.release)(shadow) };
        ret
    }
}

ffi_callback! {
    /// Encodes the slot's handle through a shadow lending its fields.
    ///
    /// # Safety
    /// As for `ASN1_item_ex_i2d`, with `pval` holding a live handle of the item.
    pub(crate) unsafe extern "C" fn ex_i2d(pval: *mut *const ASN1_VALUE, out: *mut *mut c_uchar, it: *const ASN1_ITEM, tag: c_int, aclass: c_int) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let Some(sh) = (unsafe { own(it) }) else { return -1 };
        // SAFETY: as above.
        let h = unsafe { pval.read() };
        // SAFETY: a live handle.
        let shadow = unsafe { (sh.lend)(h, Lend::Encode) };
        if shadow.is_null() {
            return -1;
        }
        // SAFETY: the item's own shadow item.
        let sit = unsafe { (sh.item)() };
        let mut sv = shadow.cast_const();
        // SAFETY: the shadow, a value of its item; the caller's output.
        let ret = unsafe { ASN1_item_ex_i2d(&raw mut sv, out, sit, tag, aclass) };
        // SAFETY: the shadow's own memory; its numbers are the handle's.
        unsafe { (sh.release)(shadow) };
        ret
    }
}
