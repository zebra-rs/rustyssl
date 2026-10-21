//! The SCTP datagram BIO's functions (`BIO_new_dgram_sctp(3)`), which only the Fedora profile
//! exports: Fedora builds OpenSSL with `enable-sctp`, and its own `openssl` tool imports them.
//! OpenSSL's headers declare them only without `OPENSSL_NO_SCTP`, so the type is `bio.h`'s.
//!
//! rustyssl has no SCTP transport, so no SCTP BIO can be made: the method's `create` fails,
//! `BIO_new_dgram_sctp` fails as OpenSSL's does where the kernel won't enable SCTP-AUTH
//! (closing the descriptor it was given under `BIO_CLOSE`), and every other BIO is not an SCTP
//! one (docs/DEVIATIONS.md).

use core::ffi::{c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    BIO, BIO_CLOSE, BIO_METHOD, BIO_TYPE_DESCRIPTOR, BIO_TYPE_SOURCE_SINK, ERR_LIB_BIO,
    ERR_R_UNSUPPORTED,
};

use super::method::{Builtin, Funcs};
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};

/// `BIO_TYPE_DGRAM_SCTP` (`bio.h`).
const BIO_TYPE_DGRAM_SCTP: c_int = 24 | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR;

/// Why every SCTP call fails.
const UNSUPPORTED: &str = "SCTP is not supported by rustyssl";

ffi_callback! {
    /// The method's `create`: there's no SCTP transport to open.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn sctp_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        let _ = b;
        err::raise_with_text(ERR_LIB_BIO, ERR_R_UNSUPPORTED, "dgram_sctp_new", UNSUPPORTED);
        0
    }
}

static DATAGRAM_SCTP: Builtin = Builtin::new(BIO_TYPE_DGRAM_SCTP, c"datagram sctp socket", || {
    Funcs { create: Some(sctp_new), ..Funcs::default() }
});

ffi_export! {
    /// Returns the SCTP datagram method, whose BIOs can't be created.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_s_datagram_sctp() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        DATAGRAM_SCTP.get()
    }
}

ffi_export! {
    /// Fails: there's no SCTP transport. Closes `fd` under `BIO_CLOSE`, as OpenSSL's frees the
    /// BIO it made on it when SCTP-AUTH can't be enabled.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_new_dgram_sctp(fd: c_int, close_flag: c_int) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        err::raise_with_text(ERR_LIB_BIO, ERR_R_UNSUPPORTED, "BIO_new_dgram_sctp", UNSUPPORTED);
        if close_flag == BIO_CLOSE && fd >= 0 {
            // SAFETY: the caller handed the descriptor over with BIO_CLOSE.
            unsafe { super::sock::BIO_closesocket(fd) };
        }
        ptr::null_mut()
    }
}

ffi_export! {
    /// 1 if `bio` is an SCTP datagram BIO: never, since none can be made.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_dgram_is_sctp(bio: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        let _ = bio;
        0
    }
}

/// `BIO_dgram_sctp_notification_handler_fn`.
type NotificationHandler = Option<unsafe extern "C" fn(*mut BIO, *mut c_void, *mut c_void)>;

ffi_export! {
    /// Fails: `b` isn't an SCTP BIO. Returns -1.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_dgram_sctp_notification_cb(b: *mut BIO, handle_notifications: NotificationHandler, context: *mut c_void) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let _ = (b, handle_notifications, context);
        err::raise_with_text(ERR_LIB_BIO, ERR_R_UNSUPPORTED, "BIO_dgram_sctp_notification_cb", UNSUPPORTED);
        -1
    }
}

ffi_export! {
    /// Fails: `b` isn't an SCTP BIO. Returns -1.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_dgram_sctp_wait_for_dry(b: *mut BIO) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let _ = b;
        err::raise_with_text(ERR_LIB_BIO, ERR_R_UNSUPPORTED, "BIO_dgram_sctp_wait_for_dry", UNSUPPORTED);
        -1
    }
}

ffi_export! {
    /// Fails: `b` isn't an SCTP BIO. Returns -1.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_dgram_sctp_msg_waiting(b: *mut BIO) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let _ = b;
        err::raise_with_text(ERR_LIB_BIO, ERR_R_UNSUPPORTED, "BIO_dgram_sctp_msg_waiting", UNSUPPORTED);
        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_sctp_bio_can_be_made() {
        // SAFETY: the built-in method.
        assert!(unsafe { super::super::BIO_new(BIO_s_datagram_sctp()) }.is_null());
        let mut fds = [0; 2];
        // SAFETY: a two-element array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: our descriptor, handed over with BIO_CLOSE.
        assert!(unsafe { BIO_new_dgram_sctp(fds[0], BIO_CLOSE) }.is_null());
        // SAFETY: the descriptor BIO_CLOSE closed.
        assert_eq!(unsafe { libc::fcntl(fds[0], libc::F_GETFD) }, -1);
        // SAFETY: our descriptor, kept with BIO_NOCLOSE.
        assert!(unsafe { BIO_new_dgram_sctp(fds[1], 0) }.is_null());
        // SAFETY: the descriptor is still ours.
        assert_eq!(unsafe { libc::close(fds[1]) }, 0);
        // SAFETY: a memory BIO.
        let mem = unsafe { super::super::BIO_new(super::super::mem::BIO_s_mem()) };
        // SAFETY: a live BIO.
        unsafe {
            assert_eq!(BIO_dgram_is_sctp(mem), 0);
            assert_eq!(BIO_dgram_sctp_wait_for_dry(mem), -1);
            assert_eq!(BIO_dgram_sctp_msg_waiting(mem), -1);
            assert_eq!(BIO_dgram_sctp_notification_cb(mem, None, ptr::null_mut()), -1);
            super::super::BIO_free(mem);
        }
    }
}
