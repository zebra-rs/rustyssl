//! `asn1_item_list.c`: OpenSSL's built-in items by index and by short name, from the table
//! codegen takes from the vendored `asn1_item_list.h` (`generated/asn1_item_list.rs`).

use core::ffi::{CStr, c_char};
use core::ptr;

use rustyssl_abi::{ASN1_ITEM, ERR_LIB_ASN1};

use crate::ffi::ffi_export;
use crate::generated::asn1_item_list::ASN1_ITEM_LIST;

ffi_export! {
    /// The `i`th built-in item, or NULL past the end.
    ///
    /// # Safety
    /// None.
    pub unsafe extern "C" fn ASN1_ITEM_get(i: usize) -> *const ASN1_ITEM
    where failure = ptr::null(), library = ERR_LIB_ASN1
    {
        match ASN1_ITEM_LIST.get(i) {
            // SAFETY: an item's accessor, with no preconditions.
            Some(item) => unsafe { item() },
            None => ptr::null(),
        }
    }
}

ffi_export! {
    /// The built-in item whose short name is `name`, or NULL (also for a NULL name, which
    /// OpenSSL would read).
    ///
    /// # Safety
    /// `name` is NULL or a NUL-terminated string.
    pub unsafe extern "C" fn ASN1_ITEM_lookup(name: *const c_char) -> *const ASN1_ITEM
    where failure = ptr::null(), library = ERR_LIB_ASN1
    {
        if name.is_null() {
            return ptr::null();
        }
        // SAFETY: the caller's string.
        let name = unsafe { CStr::from_ptr(name) };
        for item in ASN1_ITEM_LIST {
            // SAFETY: an item's accessor, with no preconditions.
            let it = unsafe { item() };
            // SAFETY: a built-in item, alive for the program.
            let Some(i) = (unsafe { it.as_ref() }) else { continue };
            if i.sname.is_null() {
                continue;
            }
            // SAFETY: the item's static short name.
            if unsafe { CStr::from_ptr(i.sname) } == name {
                return it;
            }
        }
        ptr::null()
    }
}
