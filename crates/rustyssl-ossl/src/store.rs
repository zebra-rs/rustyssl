//! `OSSL_STORE`: opening a URI (or standard input) and loading what it holds.

use core::ffi::{c_char, c_int};

use crate::abi::{OSSL_PARAM, OSSL_STORE_PARAM_INPUT_TYPE};
use crate::bio::Bio;
use crate::ffi;
use crate::pkey::Pkey;
use crate::provider::LibCtx;
use crate::ui::Passphrase;
use crate::util::{cstring, string_at};
use crate::x509::{Cert, Crl};

crate::handle!(
    /// An open store, closed (`OSSL_STORE_close`) when dropped.
    Store, OSSL_STORE_CTX, OSSL_STORE_close
);

crate::handle!(
    /// One loaded object.
    Info, OSSL_STORE_INFO, OSSL_STORE_INFO_free
);

/// The optional parameters: `OSSL_STORE_PARAM_INPUT_TYPE`, when the format is known.
struct Params {
    _value: Option<std::ffi::CString>,
    params: Option<[OSSL_PARAM; 2]>,
}

impl Params {
    fn new(input_type: Option<&str>) -> Option<Self> {
        let Some(t) = input_type else {
            return Some(Self {
                _value: None,
                params: None,
            });
        };
        let value = cstring(t)?;
        // SAFETY: the key is a static string and value outlives the params (both in self);
        // the construct function only records the pointers.
        let first = unsafe {
            ffi::OSSL_PARAM_construct_utf8_string(
                OSSL_STORE_PARAM_INPUT_TYPE.as_ptr(),
                value.as_ptr().cast_mut(),
                0,
            )
        };
        // SAFETY: no arguments.
        let end = unsafe { ffi::OSSL_PARAM_construct_end() };
        let params = [first, end];
        Some(Self {
            _value: Some(value),
            params: Some(params),
        })
    }

    fn as_ptr(&self) -> *const OSSL_PARAM {
        self.params
            .as_ref()
            .map_or(core::ptr::null(), |p| p.as_ptr())
    }
}

impl Store {
    /// `OSSL_STORE_open_ex(uri, libctx, propq, get_ui_method(), uidata, params, NULL, NULL)`.
    pub fn open(
        uri: &str,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
        uidata: &Passphrase,
        input_type: Option<&str>,
    ) -> Option<Self> {
        let u = cstring(uri)?;
        let pq = match propq {
            Some(p) => Some(cstring(p)?),
            None => None,
        };
        let params = Params::new(input_type)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: every pointer is live or NULL where the API allows it; uidata and params
        // outlive the call, and uidata outlives the store (the caller keeps it).
        Self::from_ptr(unsafe {
            ffi::OSSL_STORE_open_ex(
                u.as_ptr(),
                ctx,
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
                crate::ui::method(),
                uidata.as_ptr(),
                params.as_ptr(),
                None,
                core::ptr::null_mut(),
            )
        })
    }

    /// `OSSL_STORE_attach(bio, "file", ...)`, for standard input.
    pub fn attach(
        bio: &Bio,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
        uidata: &Passphrase,
        input_type: Option<&str>,
    ) -> Option<Self> {
        let pq = match propq {
            Some(p) => Some(cstring(p)?),
            None => None,
        };
        let params = Params::new(input_type)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: as in open; the store takes its own reference to the BIO.
        Self::from_ptr(unsafe {
            ffi::OSSL_STORE_attach(
                bio.as_ptr(),
                c"file".as_ptr(),
                ctx,
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
                crate::ui::method(),
                uidata.as_ptr(),
                params.as_ptr(),
                None,
                core::ptr::null_mut(),
            )
        })
    }

    /// `OSSL_STORE_expect`.
    pub fn expect(&self, kind: c_int) -> bool {
        // SAFETY: the store is live.
        unsafe { ffi::OSSL_STORE_expect(self.as_ptr(), kind) == 1 }
    }

    /// `OSSL_STORE_eof`.
    pub fn eof(&self) -> bool {
        // SAFETY: the store is live.
        unsafe { ffi::OSSL_STORE_eof(self.as_ptr()) != 0 }
    }

    /// `OSSL_STORE_load`.
    pub fn load(&self) -> Option<Info> {
        // SAFETY: the store is live; the info is the caller's.
        Info::from_ptr(unsafe { ffi::OSSL_STORE_load(self.as_ptr()) })
    }
}

impl Info {
    /// `OSSL_STORE_INFO_get_type`.
    pub fn kind(&self) -> c_int {
        // SAFETY: the info is live.
        unsafe { ffi::OSSL_STORE_INFO_get_type(self.as_ptr()) }
    }

    /// `OSSL_STORE_INFO_get1_PKEY`.
    pub fn pkey(&self) -> Option<Pkey> {
        // SAFETY: the info is live; get1 returns a new reference.
        Pkey::from_raw(unsafe { ffi::OSSL_STORE_INFO_get1_PKEY(self.as_ptr()) })
    }

    /// `OSSL_STORE_INFO_get1_PUBKEY`.
    pub fn pubkey(&self) -> Option<Pkey> {
        // SAFETY: as above.
        Pkey::from_raw(unsafe { ffi::OSSL_STORE_INFO_get1_PUBKEY(self.as_ptr()) })
    }

    /// `OSSL_STORE_INFO_get1_PARAMS`.
    pub fn params(&self) -> Option<Pkey> {
        // SAFETY: as above.
        Pkey::from_raw(unsafe { ffi::OSSL_STORE_INFO_get1_PARAMS(self.as_ptr()) })
    }

    /// `OSSL_STORE_INFO_get1_CERT`.
    pub fn cert(&self) -> Option<Cert> {
        // SAFETY: as above.
        Cert::from_raw(unsafe { ffi::OSSL_STORE_INFO_get1_CERT(self.as_ptr()) })
    }

    /// `OSSL_STORE_INFO_get1_CRL`.
    pub fn crl(&self) -> Option<Crl> {
        // SAFETY: as above.
        Crl::from_raw(unsafe { ffi::OSSL_STORE_INFO_get1_CRL(self.as_ptr()) })
    }
}

/// `OSSL_STORE_INFO_type_string`.
pub fn type_string(kind: c_int) -> Option<String> {
    // SAFETY: a static string or NULL for any kind.
    string_at(unsafe { ffi::OSSL_STORE_INFO_type_string(kind) }.cast::<c_char>())
}

crate::handle!(
    /// An owned `OSSL_STORE_SEARCH`.
    Search, OSSL_STORE_SEARCH, OSSL_STORE_SEARCH_free
);

impl Search {
    /// `OSSL_STORE_SEARCH_by_name` (the search copies nothing: `name` must outlive it, which
    /// the borrow ensures).
    pub fn by_name(name: &crate::x509::Name) -> Option<Self> {
        // SAFETY: the name is live.
        Self::from_ptr(unsafe { ffi::OSSL_STORE_SEARCH_by_name(name.as_ptr()) })
    }

    /// `OSSL_STORE_SEARCH_by_issuer_serial`.
    pub fn by_issuer_serial(
        issuer: &crate::x509::Name,
        serial: &crate::x509::Integer,
    ) -> Option<Self> {
        // SAFETY: both are live.
        Self::from_ptr(unsafe {
            ffi::OSSL_STORE_SEARCH_by_issuer_serial(issuer.as_ptr(), serial.as_ptr())
        })
    }

    /// `OSSL_STORE_SEARCH_by_key_fingerprint` (a NULL digest allowed).
    pub fn by_key_fingerprint(md: Option<&crate::evp::Md>, bytes: &[u8]) -> Option<Self> {
        // SAFETY: the digest is live or NULL; bytes is valid for its length.
        Self::from_ptr(unsafe {
            ffi::OSSL_STORE_SEARCH_by_key_fingerprint(
                md.map_or(core::ptr::null(), |m| m.as_ptr().cast_const()),
                bytes.as_ptr(),
                bytes.len(),
            )
        })
    }

    /// `OSSL_STORE_SEARCH_by_alias`.
    pub fn by_alias(alias: &std::ffi::CStr) -> Option<Self> {
        // SAFETY: a valid C string.
        Self::from_ptr(unsafe { ffi::OSSL_STORE_SEARCH_by_alias(alias.as_ptr()) })
    }
}

impl Store {
    /// `OSSL_STORE_open_ex(uri, libctx, propq, get_ui_method(), uidata, NULL, NULL, NULL)`,
    /// as [`Store::open`] with no parameters.
    pub fn open_plain(
        uri: &str,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
        uidata: &Passphrase,
    ) -> Option<Self> {
        Self::open(uri, libctx, propq, uidata, None)
    }

    /// `OSSL_STORE_error`.
    pub fn error(&self) -> bool {
        // SAFETY: the store is live.
        unsafe { ffi::OSSL_STORE_error(self.as_ptr()) != 0 }
    }

    /// `OSSL_STORE_supports_search`.
    pub fn supports_search(&self, criterion: c_int) -> bool {
        // SAFETY: the store is live.
        unsafe { ffi::OSSL_STORE_supports_search(self.as_ptr(), criterion) != 0 }
    }

    /// `OSSL_STORE_find` (the search must outlive the loading, as the borrow ensures for
    /// the caller's scope).
    pub fn find(&self, search: &Search) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::OSSL_STORE_find(self.as_ptr(), search.as_ptr()) == 1 }
    }

    /// `OSSL_STORE_close`: whether it succeeded.
    pub fn close(self) -> bool {
        // SAFETY: the store is owned here and closed once.
        unsafe { ffi::OSSL_STORE_close(self.into_ptr()) == 1 }
    }
}

impl Info {
    /// `OSSL_STORE_INFO_get0_NAME`.
    pub fn name(&self) -> Option<String> {
        // SAFETY: the info is live; the string is owned by it.
        string_at(unsafe { ffi::OSSL_STORE_INFO_get0_NAME(self.as_ptr()) })
    }

    /// `OSSL_STORE_INFO_get0_NAME_description`.
    pub fn name_description(&self) -> Option<String> {
        // SAFETY: as above.
        string_at(unsafe { ffi::OSSL_STORE_INFO_get0_NAME_description(self.as_ptr()) })
    }
}
