//! What the built-in providers' static tables are made of: dispatch tables, algorithm tables,
//! and the parameter descriptions their `gettable`/`settable` functions return, laid out as
//! OpenSSL's `OSSL_DISPATCH`, `OSSL_ALGORITHM`, and `OSSL_PARAM_DEFN` arrays are.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;

use rustyssl_abi::{OSSL_ALGORITHM, OSSL_DISPATCH, OSSL_PARAM};

use crate::params::UNMODIFIED;

/// A function as a dispatch table holds it, cast from its type `$ty`.
macro_rules! entry {
    ($id:expr, $f:expr, $ty:ty) => {
        rustyssl_abi::OSSL_DISPATCH {
            function_id: $id,
            // SAFETY: function pointers all have one representation; the core casts it back to
            // the type its id stands for before calling it.
            function: Some(unsafe { core::mem::transmute::<$ty, unsafe extern "C" fn()>($f) }),
        }
    };
}
pub(crate) use entry;

/// The end of a dispatch table.
pub(crate) const END: OSSL_DISPATCH = OSSL_DISPATCH {
    function_id: 0,
    function: None,
};

/// A dispatch table.
pub(crate) struct Dispatch<const N: usize>(pub(crate) [OSSL_DISPATCH; N]);

// SAFETY: function pointers only; never written.
unsafe impl<const N: usize> Sync for Dispatch<N> {}

/// An algorithm table (`OSSL_ALGORITHM`s, ended by an empty one).
pub(crate) struct Algorithms<const N: usize>(pub(crate) [OSSL_ALGORITHM; N]);

// SAFETY: static strings and tables only; never written.
unsafe impl<const N: usize> Sync for Algorithms<N> {}

const DEFAULT_PROPERTIES: *const c_char = c"provider=default".as_ptr();

/// One of the default provider's algorithms (`ALG(names, functions)` in `defltprov.c`).
pub(crate) const fn alg<const N: usize>(
    names: &'static CStr,
    table: &'static Dispatch<N>,
) -> OSSL_ALGORITHM {
    OSSL_ALGORITHM {
        algorithm_names: names.as_ptr(),
        property_definition: DEFAULT_PROPERTIES,
        implementation: table.0.as_ptr(),
        algorithm_description: ptr::null(),
    }
}

/// The end of an algorithm table.
pub(crate) const ALG_END: OSSL_ALGORITHM = OSSL_ALGORITHM {
    algorithm_names: ptr::null(),
    property_definition: ptr::null(),
    implementation: ptr::null(),
    algorithm_description: ptr::null(),
};

/// A static array of parameter descriptions, ended by an empty one.
pub(crate) struct Params<const N: usize>(pub(crate) [OSSL_PARAM; N]);

// SAFETY: the keys are static strings; the arrays are never written.
unsafe impl<const N: usize> Sync for Params<N> {}

/// `OSSL_PARAM_DEFN(key, type, NULL, size)`: a description with the size the type's
/// `OSSL_PARAM_*` macro gives it (`sizeof(size_t)` for `OSSL_PARAM_size_t`, 0 for strings),
/// unmodified.
pub(crate) const fn defn(key: &'static CStr, data_type: c_int, data_size: usize) -> OSSL_PARAM {
    OSSL_PARAM {
        key: key.as_ptr(),
        data_type: data_type.cast_unsigned(),
        data: ptr::null_mut(),
        data_size,
        return_size: UNMODIFIED,
    }
}

/// A description written out as `{ key, type, NULL, 0, 0 }`, as some of the reference's lists
/// are, instead of with an `OSSL_PARAM_*` macro.
pub(crate) const fn bare(key: &'static CStr, data_type: c_int) -> OSSL_PARAM {
    OSSL_PARAM {
        key: key.as_ptr(),
        data_type: data_type.cast_unsigned(),
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    }
}

/// `OSSL_PARAM_END`.
pub(crate) const PARAM_END: OSSL_PARAM = OSSL_PARAM {
    key: ptr::null(),
    data_type: 0,
    data: ptr::null_mut(),
    data_size: 0,
    return_size: 0,
};
