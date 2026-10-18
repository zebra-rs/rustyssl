//! Kernel TLS, which the default build leaves out (`OPENSSL_NO_KTLS`): no BIO reports kTLS
//! (`BIO_CTRL_GET_KTLS_SEND`/`_RECV` fall through to 0), `SSL_OP_ENABLE_KTLS` is kept but
//! changes nothing, and `SSL_sendfile` fails as the reference's does.

use core::ffi::c_int;

use libc::off_t;
use rustyssl_abi::{
    ERR_LIB_SSL, SSL, SSL_NOTHING, SSL_R_PROTOCOL_IS_SHUTDOWN, SSL_R_UNINITIALIZED,
    SSL_SENT_SHUTDOWN,
};

use super::conn::ssl;
use crate::err;
use crate::ffi::ffi_export;

ffi_export! {
    /// Sends a file through kernel TLS: never possible without kTLS, so -1 with
    /// `SSL_R_UNINITIALIZED` once the connection has a role and isn't shut down (0 for NULL).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_sendfile(s: *mut SSL, _fd: c_int, _offset: off_t, _size: usize, _flags: c_int) -> isize
    where failure = -1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let mut st = x.state();
        if st.handshake_func.is_some() && st.shutdown & SSL_SENT_SHUTDOWN != 0 {
            st.rwstate = SSL_NOTHING;
            drop(st);
            err::raise(ERR_LIB_SSL, SSL_R_PROTOCOL_IS_SHUTDOWN, "SSL_sendfile");
            return -1;
        }
        drop(st);
        // No role yet, or (`BIO_get_ktls_send` being 0 in this build) no kTLS on the BIO.
        err::raise(ERR_LIB_SSL, SSL_R_UNINITIALIZED, "SSL_sendfile");
        -1
    }
}
