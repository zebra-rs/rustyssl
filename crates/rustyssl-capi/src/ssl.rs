//! libssl's functions, written as `rustyssl_private_*` twins that libssl's generated
//! forwarders call (ADR 0001): library initialization (`ssl_init.c`) here; the methods, the
//! context and connection objects, their certificates and keys, and the CA lists in the
//! modules. The handshake (ADR 0002) plugs into [`conn::SslState`].

pub(crate) mod accessors;
pub(crate) mod apis;
pub(crate) mod bio_ssl;
pub(crate) mod ca;
pub(crate) mod cert;
pub(crate) mod cert_ctrl;
pub(crate) mod check_chain;
pub(crate) mod ciphers;
pub(crate) mod clienthello;
pub(crate) mod conf;
pub(crate) mod conn;
pub(crate) mod ct;
pub(crate) mod ctx;
pub(crate) mod custom;
pub(crate) mod dane;
pub(crate) mod dtls;
pub(crate) mod dup;
pub(crate) mod eap;
pub(crate) mod early;
pub(crate) mod io;
pub(crate) mod keys;
pub(crate) mod ktls;
pub(crate) mod lists;
pub(crate) mod method;
pub(crate) mod misc;
pub(crate) mod npn;
mod ocsp_req;
pub(crate) mod ocsp_resp;
pub(crate) mod psk;
pub(crate) mod quic_provider;
pub(crate) mod quic_tls;
pub(crate) mod requests;
pub(crate) mod sess_asn1;
pub(crate) mod sess_cache;
pub(crate) mod session;
pub(crate) mod srp;
pub(crate) mod srtp;
pub(crate) mod tls_provider;
pub(crate) mod trace;
pub(crate) mod types;

use core::ffi::{c_int, c_long};

use rustyssl_abi::{
    ERR_LIB_SSL, OPENSSL_INIT_ADD_ALL_CIPHERS, OPENSSL_INIT_ADD_ALL_DIGESTS,
    OPENSSL_INIT_LOAD_CONFIG, OPENSSL_INIT_NO_LOAD_CONFIG, OPENSSL_INIT_SETTINGS,
};

use crate::ffi::ffi_export;
use crate::init;

/// An `OPENSSL_INIT_*` flag as the options' type.
fn flag(f: c_long) -> u64 {
    f.cast_unsigned()
}

ffi_export! {
    /// libssl's `OPENSSL_init_ssl`: `OPENSSL_init_crypto` with `opts`, the cipher and digest
    /// tables, and (unless `OPENSSL_INIT_NO_LOAD_CONFIG`) the configuration. libssl's own
    /// set-up (its cipher list and compression methods) comes with libssl. Returns 1, or 0.
    ///
    /// # Safety
    /// `settings` is NULL or a live settings object.
    pub unsafe extern "C" fn rustyssl_private_OPENSSL_init_ssl(opts: u64, settings: *const OPENSSL_INIT_SETTINGS) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let mut opts = opts | flag(OPENSSL_INIT_ADD_ALL_CIPHERS) | flag(OPENSSL_INIT_ADD_ALL_DIGESTS);
        if opts & flag(OPENSSL_INIT_NO_LOAD_CONFIG) == 0 {
            opts |= flag(OPENSSL_INIT_LOAD_CONFIG);
        }
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { init::OPENSSL_init_crypto(opts, settings) } != 0)
    }
}
