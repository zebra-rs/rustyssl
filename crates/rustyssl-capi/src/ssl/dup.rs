//! `SSL_dup`: a quiescent connection's configuration (and session) copied into a new one; any
//! other connection is shared by reference.

use core::ptr;

use rustyssl_abi::{CRYPTO_EX_INDEX_SSL, ERR_LIB_SSL, SSL, stack_st_X509_NAME};

use super::ca::rustyssl_private_SSL_dup_CA_list;
use super::conn::{
    Role, rustyssl_private_SSL_free, rustyssl_private_SSL_get_SSL_CTX,
    rustyssl_private_SSL_get_verify_depth, rustyssl_private_SSL_in_before,
    rustyssl_private_SSL_in_init, rustyssl_private_SSL_new, rustyssl_private_SSL_set_accept_state,
    rustyssl_private_SSL_set_connect_state, rustyssl_private_SSL_set_verify_depth,
    rustyssl_private_SSL_up_ref, ssl,
};
use super::ctx::name_free;
use super::dane::rustyssl_private_SSL_dane_tlsa_add;
use super::sess_cache::rustyssl_private_SSL_copy_session_id;
use crate::ex_data::CRYPTO_dup_ex_data;
use crate::ffi::ffi_export;
use crate::stack::OPENSSL_sk_pop_free;
use crate::x509::vpm::X509_VERIFY_PARAM_inherit;

/// `dup_ca_names`: a copy of `src` (NULL stays NULL), or `None`.
///
/// # Safety
/// `src` is NULL or a live list of names.
unsafe fn dup_names(src: *mut stack_st_X509_NAME) -> Option<*mut stack_st_X509_NAME> {
    if src.is_null() {
        return Some(ptr::null_mut());
    }
    // SAFETY: the caller's guarantee.
    let d = unsafe { rustyssl_private_SSL_dup_CA_list(src) };
    (!d.is_null()).then_some(d)
}

/// Copies `s`'s configuration into the new connection `ret` (the body of `SSL_dup`).
///
/// # Safety
/// `s` and `ret` are live, distinct connections.
unsafe fn copy_into(ret: *mut SSL, s: *mut SSL) -> bool {
    // SAFETY: the caller's guarantee.
    let (Some(to), Some(from)) = (unsafe { ssl(ret) }, unsafe { ssl(s) }) else {
        return false;
    };
    if from.state().sess.session.is_null() {
        // No session: the method, a copy of the certificates, and the session ID context.
        let (method, cert, sid_ctx) = {
            let st = from.state();
            (st.method, st.cert.dup(), st.sid_ctx.clone())
        };
        let Some(cert) = cert else { return false };
        let old = {
            let mut st = to.state();
            if !ptr::eq(st.method, method) {
                let same_version = st.method.version == method.version;
                st.method = method;
                if !same_version {
                    st.version = method.idle_version();
                }
            }
            st.sid_ctx = sid_ctx;
            core::mem::replace(&mut st.cert, cert)
        };
        drop(old);
    } else {
        // SAFETY: both live.
        if unsafe { rustyssl_private_SSL_copy_session_id(ret, s) } == 0 {
            return false;
        }
    }

    // `ssl_dane_dup`.
    let dane = from.state().lists.dane.dup_records();
    if let Some((flags, recs)) = dane {
        to.state().lists.dane.reset_enabled(flags);
        for (usage, selector, mtype, data) in recs {
            // SAFETY: the new connection; the record's data.
            let r = unsafe {
                rustyssl_private_SSL_dane_tlsa_add(
                    ret,
                    usage,
                    selector,
                    mtype,
                    data.as_ptr(),
                    data.len(),
                )
            };
            if r <= 0 {
                return false;
            }
        }
    }

    // SAFETY: the live original.
    let depth = unsafe { rustyssl_private_SSL_get_verify_depth(s) };
    let (ca, client_ca, ciphers, role, server, shutdown, hit) = {
        let f = from.state();
        let mut t = to.state();
        t.version = f.version;
        t.options = f.options;
        t.min_proto_version = f.min_proto_version;
        t.max_proto_version = f.max_proto_version;
        t.mode = f.mode;
        t.max_cert_list = f.max_cert_list;
        t.read_ahead = f.read_ahead;
        t.msg_callback = f.msg_callback;
        t.msg_callback_arg = f.msg_callback_arg;
        t.verify_mode = f.verify_mode;
        if f.verify_callback.is_some() {
            t.verify_callback = f.verify_callback;
        }
        t.generate_session_id = f.generate_session_id;
        t.info_callback = f.info_callback;
        t.default_passwd_callback = f.default_passwd_callback;
        t.default_passwd_callback_userdata = f.default_passwd_callback_userdata;
        t.lists
            .server_cert_type
            .clone_from(&f.lists.server_cert_type);
        t.lists
            .client_cert_type
            .clone_from(&f.lists.client_cert_type);
        t.ct.callback = f.ct.callback;
        t.ct.arg = f.ct.arg;
        t.status_type = f.status_type;
        let ciphers = (f.ciphers.list.dup(), f.ciphers.by_id.dup());
        let ca = (f.ca_names, f.client_ca_names);
        let out = (
            ca.0,
            ca.1,
            ciphers,
            f.handshake_func,
            f.server,
            f.shutdown,
            f.hit,
        );
        drop(t);
        out
    };
    // SAFETY: the new connection.
    unsafe { rustyssl_private_SSL_set_verify_depth(ret, depth) };

    // SAFETY: both connections' application data (`ret`'s isn't shared yet).
    if unsafe { CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_SSL, to.ex_data(), from.ex_data()) } == 0 {
        return false;
    }

    match role {
        // SAFETY: the new connection.
        Some(Role::Accept) => unsafe { rustyssl_private_SSL_set_accept_state(ret) },
        // SAFETY: as above.
        Some(Role::Connect) => unsafe { rustyssl_private_SSL_set_connect_state(ret) },
        None => {}
    }
    {
        let mut t = to.state();
        t.server = server;
        t.shutdown = shutdown;
        t.hit = hit;
    }

    // SAFETY: the two connections' own parameters.
    unsafe { X509_VERIFY_PARAM_inherit(to.param, from.param) };

    let (Some(list), Some(by_id)) = ciphers else {
        return false;
    };
    let old = {
        let mut t = to.state();
        (
            core::mem::replace(&mut t.ciphers.list, list),
            core::mem::replace(&mut t.ciphers.by_id, by_id),
        )
    };
    drop(old);

    // The original's lists, read under no lock: an application doesn't change a connection
    // while duplicating it, as OpenSSL assumes.
    // SAFETY: the original's live lists, or NULL.
    let (Some(ca), Some(client_ca)) = (unsafe { dup_names(ca) }, unsafe { dup_names(client_ca) })
    else {
        return false;
    };
    let mut t = to.state();
    let old = (
        core::mem::replace(&mut t.ca_names, ca),
        core::mem::replace(&mut t.client_ca_names, client_ca),
    );
    drop(t);
    // SAFETY: the new connection's former lists, no longer referenced.
    unsafe { OPENSSL_sk_pop_free(old.0.cast(), Some(name_free)) };
    // SAFETY: as above.
    unsafe { OPENSSL_sk_pop_free(old.1.cast(), Some(name_free)) };
    true
}

ffi_export! {
    /// A copy of a connection that hasn't started: a new connection of its context with its
    /// configuration and session. A connection that has started is shared instead (a reference
    /// taken, the same pointer returned). NULL on failure.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_dup(s: *mut SSL) -> *mut SSL
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { super::quic::of(s) }.is_some() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        if unsafe { ssl(s) }.is_none() {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        if unsafe { rustyssl_private_SSL_in_init(s) } == 0 || unsafe { rustyssl_private_SSL_in_before(s) } == 0 {
            // SAFETY: as above.
            unsafe { rustyssl_private_SSL_up_ref(s) };
            return s;
        }
        // SAFETY: as above.
        let c = unsafe { rustyssl_private_SSL_get_SSL_CTX(s) };
        // SAFETY: the connection's live context.
        let ret = unsafe { rustyssl_private_SSL_new(c) };
        if ret.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the original and the new connection.
        if unsafe { copy_into(ret, s) } {
            return ret;
        }
        // SAFETY: the new connection, ours.
        unsafe { rustyssl_private_SSL_free(ret) };
        ptr::null_mut()
    }
}
