//! The `SSL_METHOD`s (`methods.c`): a method fixes the protocol family (TLS or DTLS), the
//! version (one, or any), and which roles it can take. They are static; a method pointer from
//! anywhere else is not one of ours.

use core::ffi::c_int;
use core::ptr;

use rustyssl_abi::{
    DTLS_ANY_VERSION, DTLS1_2_VERSION, DTLS1_VERSION, ERR_LIB_SSL, SSL_METHOD, TLS_ANY_VERSION,
    TLS1_1_VERSION, TLS1_2_VERSION, TLS1_VERSION,
};

use crate::ffi::ffi_export;

/// A method (`struct ssl_method_st`, opaque to applications).
#[derive(Debug)]
pub(crate) struct Method {
    /// The version (`TLS_ANY_VERSION`/`DTLS_ANY_VERSION` for the version-flexible ones).
    pub(crate) version: c_int,
    /// Whether it is a DTLS method.
    pub(crate) dtls: bool,
    /// Whether it can act as a client (its `ssl_connect` is defined).
    pub(crate) client: bool,
    /// Whether it can act as a server (its `ssl_accept` is defined).
    pub(crate) server: bool,
}

impl Method {
    /// The handle C sees.
    pub(crate) fn handle(&'static self) -> *const SSL_METHOD {
        ptr::from_ref(self).cast()
    }

    /// The version a connection reports before a handshake (`tls1_clear`/`dtls1_clear`): a
    /// version-flexible method's highest, otherwise its own.
    pub(crate) fn idle_version(&self) -> c_int {
        match self.version {
            TLS_ANY_VERSION => rustyssl_abi::TLS1_3_VERSION,
            DTLS_ANY_VERSION => DTLS1_2_VERSION,
            v => v,
        }
    }
}

macro_rules! methods {
    ($($stat:ident = $version:expr, $dtls:expr, $client:expr, $server:expr;)*) => {
        $(static $stat: Method = Method { version: $version, dtls: $dtls, client: $client, server: $server };)*
        /// Every method.
        static ALL: &[&Method] = &[$(&$stat,)*];
    };
}

methods! {
    TLS = TLS_ANY_VERSION, false, true, true;
    TLS_CLIENT = TLS_ANY_VERSION, false, true, false;
    TLS_SERVER = TLS_ANY_VERSION, false, false, true;
    TLS1 = TLS1_VERSION, false, true, true;
    TLS1_CLIENT = TLS1_VERSION, false, true, false;
    TLS1_SERVER = TLS1_VERSION, false, false, true;
    TLS1_1 = TLS1_1_VERSION, false, true, true;
    TLS1_1_CLIENT = TLS1_1_VERSION, false, true, false;
    TLS1_1_SERVER = TLS1_1_VERSION, false, false, true;
    TLS1_2 = TLS1_2_VERSION, false, true, true;
    TLS1_2_CLIENT = TLS1_2_VERSION, false, true, false;
    TLS1_2_SERVER = TLS1_2_VERSION, false, false, true;
    DTLS = DTLS_ANY_VERSION, true, true, true;
    DTLS_CLIENT = DTLS_ANY_VERSION, true, true, false;
    DTLS_SERVER = DTLS_ANY_VERSION, true, false, true;
    DTLS1 = DTLS1_VERSION, true, true, true;
    DTLS1_CLIENT = DTLS1_VERSION, true, true, false;
    DTLS1_SERVER = DTLS1_VERSION, true, false, true;
    DTLS1_2 = DTLS1_2_VERSION, true, true, true;
    DTLS1_2_CLIENT = DTLS1_2_VERSION, true, true, false;
    DTLS1_2_SERVER = DTLS1_2_VERSION, true, false, true;
}

/// The method behind a handle, if it is one of ours.
pub(crate) fn method_of(m: *const SSL_METHOD) -> Option<&'static Method> {
    ALL.iter().copied().find(|x| ptr::eq(x.handle(), m))
}

/// The default session timeout of every method, in seconds (`tls1_default_timeout`,
/// `dtls1_default_timeout`: two hours).
pub(crate) const DEFAULT_TIMEOUT: core::ffi::c_long = 2 * 60 * 60;

ffi_export! {
    /// The version-flexible TLS method, for either role.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_TLS_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        TLS.handle()
    }
}

ffi_export! {
    /// The version-flexible TLS method for clients.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_TLS_client_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        TLS_CLIENT.handle()
    }
}

ffi_export! {
    /// The version-flexible TLS method for servers.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_TLS_server_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        TLS_SERVER.handle()
    }
}

ffi_export! {
    /// TLS 1.0 only (deprecated), for either role.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_TLSv1_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        TLS1.handle()
    }
}

ffi_export! {
    /// TLS 1.0 only (deprecated), for clients.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_TLSv1_client_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        TLS1_CLIENT.handle()
    }
}

ffi_export! {
    /// TLS 1.0 only (deprecated), for servers.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_TLSv1_server_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        TLS1_SERVER.handle()
    }
}

ffi_export! {
    /// TLS 1.1 only (deprecated), for either role.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_TLSv1_1_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        TLS1_1.handle()
    }
}

ffi_export! {
    /// TLS 1.1 only (deprecated), for clients.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_TLSv1_1_client_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        TLS1_1_CLIENT.handle()
    }
}

ffi_export! {
    /// TLS 1.1 only (deprecated), for servers.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_TLSv1_1_server_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        TLS1_1_SERVER.handle()
    }
}

ffi_export! {
    /// TLS 1.2 only (deprecated), for either role.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_TLSv1_2_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        TLS1_2.handle()
    }
}

ffi_export! {
    /// TLS 1.2 only (deprecated), for clients.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_TLSv1_2_client_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        TLS1_2_CLIENT.handle()
    }
}

ffi_export! {
    /// TLS 1.2 only (deprecated), for servers.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_TLSv1_2_server_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        TLS1_2_SERVER.handle()
    }
}

ffi_export! {
    /// The version-flexible DTLS method, for either role.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_DTLS_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        DTLS.handle()
    }
}

ffi_export! {
    /// The version-flexible DTLS method for clients.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_DTLS_client_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        DTLS_CLIENT.handle()
    }
}

ffi_export! {
    /// The version-flexible DTLS method for servers.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_DTLS_server_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        DTLS_SERVER.handle()
    }
}

ffi_export! {
    /// DTLS 1.0 only (deprecated), for either role.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_DTLSv1_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        DTLS1.handle()
    }
}

ffi_export! {
    /// DTLS 1.0 only (deprecated), for clients.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_DTLSv1_client_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        DTLS1_CLIENT.handle()
    }
}

ffi_export! {
    /// DTLS 1.0 only (deprecated), for servers.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_DTLSv1_server_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        DTLS1_SERVER.handle()
    }
}

ffi_export! {
    /// DTLS 1.2 only, for either role.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_DTLSv1_2_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        DTLS1_2.handle()
    }
}

ffi_export! {
    /// DTLS 1.2 only, for clients.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_DTLSv1_2_client_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        DTLS1_2_CLIENT.handle()
    }
}

ffi_export! {
    /// DTLS 1.2 only, for servers.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_DTLSv1_2_server_method() -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        DTLS1_2_SERVER.handle()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_method_is_found_by_its_handle() {
        for m in ALL {
            assert!(method_of(m.handle()).is_some_and(|x| ptr::eq(x, *m)));
        }
        assert!(method_of(ptr::null()).is_none());
    }

    #[test]
    fn idle_versions_are_the_highest_of_a_flexible_method() {
        assert_eq!(TLS.idle_version(), rustyssl_abi::TLS1_3_VERSION);
        assert_eq!(DTLS_CLIENT.idle_version(), DTLS1_2_VERSION);
        assert_eq!(TLS1_1.idle_version(), TLS1_1_VERSION);
    }
}
