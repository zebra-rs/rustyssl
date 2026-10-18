//! `SSL_CONF` (`ssl_conf.c`) and the configuration's `ssl_conf` sets (`ssl_mcnf.c`): commands
//! by name, from a file (`Groups = ...`) or a command line (`-groups ...`), applied to a context
//! or a connection through their public setters, as OpenSSL applies them.
//!
//! An `SSL_CONF_CTX` refers to its `SSL_CTX` or `SSL` without holding a reference, as
//! OpenSSL's does. Its lock is never held while a command runs: commands call setters that may
//! call the application (a password callback, say).

use core::ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong};
use core::ptr;
use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    BIO_C_SET_FILENAME, BIO_CLOSE, BIO_CTRL_EOF, BIO_FP_READ, DTLS1_2_VERSION, DTLS1_VERSION,
    ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER, EVP_PKEY, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
    OSSL_LIB_CTX, SSL, SSL_CERT_FLAG_TLS_STRICT, SSL_CONF_CTX, SSL_CONF_FLAG_CERTIFICATE,
    SSL_CONF_FLAG_CLIENT, SSL_CONF_FLAG_CMDLINE, SSL_CONF_FLAG_FILE, SSL_CONF_FLAG_REQUIRE_PRIVATE,
    SSL_CONF_FLAG_SERVER, SSL_CONF_FLAG_SHOW_ERRORS, SSL_CONF_TYPE_DIR, SSL_CONF_TYPE_FILE,
    SSL_CONF_TYPE_NONE, SSL_CONF_TYPE_STORE, SSL_CONF_TYPE_STRING, SSL_CONF_TYPE_UNKNOWN,
    SSL_CTRL_SET_CLIENT_SIGALGS_LIST, SSL_CTRL_SET_GROUPS_LIST, SSL_CTRL_SET_SIGALGS_LIST, SSL_CTX,
    SSL_FILETYPE_PEM, SSL_OP_ALL, SSL_OP_ALLOW_CLIENT_RENEGOTIATION, SSL_OP_ALLOW_NO_DHE_KEX,
    SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION, SSL_OP_CIPHER_SERVER_PREFERENCE,
    SSL_OP_DISABLE_TLSEXT_CA_NAMES, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS, SSL_OP_ENABLE_KTLS,
    SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE, SSL_OP_ENABLE_MIDDLEBOX_COMPAT,
    SSL_OP_IGNORE_UNEXPECTED_EOF, SSL_OP_LEGACY_SERVER_CONNECT, SSL_OP_NO_ANTI_REPLAY,
    SSL_OP_NO_COMPRESSION, SSL_OP_NO_DTLSv1, SSL_OP_NO_DTLSv1_2, SSL_OP_NO_ENCRYPT_THEN_MAC,
    SSL_OP_NO_EXTENDED_MASTER_SECRET, SSL_OP_NO_RENEGOTIATION,
    SSL_OP_NO_RX_CERTIFICATE_COMPRESSION, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
    SSL_OP_NO_SSL_MASK, SSL_OP_NO_SSLv2, SSL_OP_NO_SSLv3, SSL_OP_NO_TICKET, SSL_OP_NO_TLSv1,
    SSL_OP_NO_TLSv1_1, SSL_OP_NO_TLSv1_2, SSL_OP_NO_TLSv1_3, SSL_OP_NO_TX_CERTIFICATE_COMPRESSION,
    SSL_OP_PREFER_NO_DHE_KEX, SSL_OP_PRIORITIZE_CHACHA, SSL_OP_SINGLE_DH_USE,
    SSL_OP_SINGLE_ECDH_USE, SSL_R_BAD_VALUE, SSL_R_INVALID_CONFIGURATION_NAME,
    SSL_R_INVALID_NULL_CMD_NAME, SSL_R_UNKNOWN_CMD_NAME, SSL_VERIFY_CLIENT_ONCE,
    SSL_VERIFY_FAIL_IF_NO_PEER_CERT, SSL_VERIFY_PEER, SSL_VERIFY_POST_HANDSHAKE, SSL3_VERSION,
    TLS1_1_VERSION, TLS1_2_VERSION, TLS1_3_VERSION, TLS1_VERSION, X509_STORE, stack_st_X509_NAME,
};

use super::ca::{
    rustyssl_private_SSL_CTX_set0_CA_list, rustyssl_private_SSL_add_dir_cert_subjects_to_stack,
    rustyssl_private_SSL_add_file_cert_subjects_to_stack,
    rustyssl_private_SSL_add_store_cert_subjects_to_stack, rustyssl_private_SSL_set0_CA_list,
};
use super::cert::Cert;
use super::ciphers::{
    rustyssl_private_SSL_CTX_set_cipher_list, rustyssl_private_SSL_CTX_set_ciphersuites,
    rustyssl_private_SSL_set_cipher_list, rustyssl_private_SSL_set_ciphersuites,
};
use super::conn::{
    rustyssl_private_SSL_ctrl, rustyssl_private_SSL_is_quic,
    rustyssl_private_SSL_set_block_padding_ex, ssl,
};
use super::ctx::{
    ctx, name_free, rustyssl_private_SSL_CTX_ctrl, rustyssl_private_SSL_CTX_set_block_padding_ex,
    set_version_bound,
};
use super::keys::{
    rustyssl_private_SSL_CTX_set0_tmp_dh_pkey, rustyssl_private_SSL_CTX_use_PrivateKey_file,
    rustyssl_private_SSL_CTX_use_certificate_chain_file, rustyssl_private_SSL_set0_tmp_dh_pkey,
    rustyssl_private_SSL_use_PrivateKey_file, rustyssl_private_SSL_use_certificate_chain_file,
};
use super::types::SSL_PKEY_NUM;
use crate::bio::{BIO_ctrl, BIO_free, BIO_new, file::BIO_s_file};
use crate::decoder::ctx::{OSSL_DECODER_CTX_free, OSSL_DECODER_from_bio};
use crate::decoder::pkey::OSSL_DECODER_CTX_new_for_pkey;
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::pkey::EVP_PKEY_free;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::libctx::{OSSL_LIB_CTX_get_conf_diagnostics, OSSL_LIB_CTX_set0_default};
use crate::stack::{OPENSSL_sk_new_null, OPENSSL_sk_pop_free};
use crate::string::OPENSSL_strtoul;
use crate::x509::store::{
    X509_STORE_free, X509_STORE_load_file_ex, X509_STORE_load_path, X509_STORE_load_store_ex,
    X509_STORE_new, X509_STORE_up_ref,
};

/// A name's sense is inverted: `TLSv1` clears `SSL_OP_NO_TLSv1` (`SSL_TFLAG_INV`).
const TFLAG_INV: c_uint = 0x1;
/// The kind of setting a name changes (`SSL_TFLAG_TYPE_MASK`): options, certificate flags
/// (`SSL_TFLAG_CERT`), or the verify mode (`SSL_TFLAG_VFY`).
const TFLAG_TYPE_MASK: c_uint = 0xf00;
/// See [`TFLAG_TYPE_MASK`].
const TFLAG_CERT: c_uint = 0x100;
/// See [`TFLAG_TYPE_MASK`].
const TFLAG_VFY: c_uint = 0x200;

/// A flag, as `c_uint`.
fn fl(f: c_int) -> c_uint {
    f.cast_unsigned()
}

/// Client, server, or both (`SSL_TFLAG_BOTH`).
fn both() -> c_uint {
    fl(SSL_CONF_FLAG_CLIENT) | fl(SSL_CONF_FLAG_SERVER)
}

/// An option name of a list command (`ssl_flag_tbl`).
struct Flag {
    name: &'static str,
    flags: c_uint,
    value: u64,
}

/// The settings an `SSL_CONF_CTX` keeps (`ssl_conf_ctx_st`).
struct ConfState {
    flags: c_uint,
    prefix: Option<CString>,
    ctx: *mut SSL_CTX,
    ssl: *mut SSL,
    /// Whether options apply to `ctx` or `ssl` (OpenSSL's `poptions` set).
    target: bool,
    /// The certificate file of each slot, for `SSL_CONF_FLAG_REQUIRE_PRIVATE`.
    cert_filename: Vec<Option<CString>>,
    /// The CA names of the `*CA*` request commands (owned), or NULL.
    canames: *mut stack_st_X509_NAME,
}

impl Drop for ConfState {
    fn drop(&mut self) {
        // SAFETY: our own list of names, or NULL.
        unsafe { OPENSSL_sk_pop_free(self.canames.cast(), Some(name_free)) };
    }
}

/// An `SSL_CONF_CTX`.
pub(crate) struct ConfCtx {
    state: Mutex<ConfState>,
}

// SAFETY: the pointers are the application's objects, which it shares under its own rules (an
// `SSL_CONF_CTX` is used by one thread at a time, as in OpenSSL), and the names list is owned.
unsafe impl Send for ConfCtx {}
// SAFETY: as above; the state is behind the mutex.
unsafe impl Sync for ConfCtx {}

handle_type!(SSL_CONF_CTX => ConfCtx);

impl ConfCtx {
    fn state(&self) -> MutexGuard<'_, ConfState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What a command needs, copied out so no lock is held while it runs.
    fn target(&self) -> Target {
        let st = self.state();
        Target {
            flags: st.flags,
            ctx: st.ctx,
            ssl: st.ssl,
            options: st.target,
        }
    }
}

/// The object a command acts on.
#[derive(Clone, Copy)]
struct Target {
    flags: c_uint,
    ctx: *mut SSL_CTX,
    ssl: *mut SSL,
    options: bool,
}

impl Target {
    fn has(self, f: c_int) -> bool {
        self.flags & fl(f) != 0
    }

    /// Runs `f` on the target's options, certificate flags, and verify mode (OpenSSL's
    /// `poptions`, `pcert_flags`, `pvfy_flags`).
    fn with_settings(self, f: impl FnOnce(&mut u64, &mut u32, &mut c_int)) {
        if !self.ssl.is_null() {
            // SAFETY: the application's connection, live while the `SSL_CONF_CTX` uses it.
            if let Some(x) = unsafe { ssl(self.ssl) } {
                let mut st = x.state();
                let st = &mut *st;
                f(
                    &mut st.options,
                    &mut st.cert.cert_flags,
                    &mut st.verify_mode,
                );
            }
        // SAFETY: as above, the application's context.
        } else if let Some(x) = unsafe { ctx(self.ctx) } {
            let mut st = x.state();
            let st = &mut *st;
            f(
                &mut st.options,
                &mut st.cert.cert_flags,
                &mut st.verify_mode,
            );
        }
    }

    /// Runs `f` on the target's certificate configuration.
    fn with_cert<R>(self, f: impl FnOnce(&mut Cert) -> R) -> Option<R> {
        if !self.ctx.is_null() {
            // SAFETY: the application's context.
            let x = unsafe { ctx(self.ctx) }?;
            return Some(f(&mut x.state().cert));
        }
        // SAFETY: the application's connection.
        let x = unsafe { ssl(self.ssl) }?;
        Some(f(&mut x.state().cert))
    }

    /// The library context and property query of the target's context (`ctx->libctx`).
    fn libctx(self) -> (*mut OSSL_LIB_CTX, Option<CString>) {
        let c = if self.ssl.is_null() {
            self.ctx
        } else {
            // SAFETY: the application's connection.
            unsafe { ssl(self.ssl) }.map_or(ptr::null_mut(), |x| x.state().ctx)
        };
        // SAFETY: the context, which the connection holds a reference to.
        unsafe { ctx(c) }.map_or((ptr::null_mut(), None), |x| (x.libctx, x.propq.clone()))
    }

    /// `ssl_set_option`.
    fn set_option(self, name_flags: c_uint, value: u64, onoff: bool) {
        if !self.options {
            return;
        }
        let onoff = onoff ^ (name_flags & TFLAG_INV != 0);
        let kind = name_flags & TFLAG_TYPE_MASK;
        // The certificate flags and the verify mode are 32 bits, as OpenSSL's `uint32_t`s.
        let small = u32::try_from(value & 0xffff_ffff).unwrap_or(0);
        self.with_settings(|options, cert_flags, verify_mode| match kind {
            0 => {
                if onoff {
                    *options |= value;
                } else {
                    *options &= !value;
                }
            }
            TFLAG_CERT => {
                if onoff {
                    *cert_flags |= small;
                } else {
                    *cert_flags &= !small;
                }
            }
            TFLAG_VFY => {
                let mut v = verify_mode.cast_unsigned();
                if onoff {
                    v |= small;
                } else {
                    v &= !small;
                }
                *verify_mode = v.cast_signed();
            }
            _ => {}
        });
    }

    /// `ssl_set_option_list` with `tbl`, for `CONF_parse_list` (`+name` sets, `-name` clears).
    fn option_list(self, tbl: &[Flag], elem: Option<&[u8]>) -> c_int {
        let Some(mut e) = elem else { return 0 };
        let mut onoff = true;
        match e.split_first() {
            Some((b'+', rest)) => e = rest,
            Some((b'-', rest)) => {
                e = rest;
                onoff = false;
            }
            _ => {}
        }
        for t in tbl {
            if self.flags & t.flags & both() == 0 || !t.name.as_bytes().eq_ignore_ascii_case(e) {
                continue;
            }
            self.set_option(t.flags, t.value, onoff);
            return 1;
        }
        0
    }

    /// Runs `tbl` over a comma-separated list.
    fn options_from(self, tbl: &[Flag], value: &CStr) -> c_int {
        super::lists::parse_list(value.to_bytes(), b',', true, &mut |e| {
            self.option_list(tbl, e)
        })
    }
}

/// An option for both ends.
fn both_flag(name: &'static str, value: u64) -> Flag {
    Flag {
        name,
        flags: both(),
        value,
    }
}

/// An inverted option for both ends.
fn inv(name: &'static str, value: u64) -> Flag {
    Flag {
        name,
        flags: TFLAG_INV | both(),
        value,
    }
}

/// A server option.
fn srv(name: &'static str, value: u64) -> Flag {
    Flag {
        name,
        flags: fl(SSL_CONF_FLAG_SERVER),
        value,
    }
}

/// A verify mode setting for one end.
fn vfy(name: &'static str, end: c_int, value: c_int) -> Flag {
    Flag {
        name,
        flags: TFLAG_VFY | fl(end),
        value: u64::from(value.cast_unsigned()),
    }
}

/// An `SSL_OP_*` that the headers define as `int`.
fn op(v: c_int) -> u64 {
    u64::from(v.cast_unsigned())
}

/// `Protocol`'s names (`ssl_protocol_list`).
fn protocol_list() -> [Flag; 9] {
    [
        inv("ALL", SSL_OP_NO_SSL_MASK),
        inv("SSLv2", op(SSL_OP_NO_SSLv2)),
        inv("SSLv3", SSL_OP_NO_SSLv3),
        inv("TLSv1", SSL_OP_NO_TLSv1),
        inv("TLSv1.1", SSL_OP_NO_TLSv1_1),
        inv("TLSv1.2", SSL_OP_NO_TLSv1_2),
        inv("TLSv1.3", SSL_OP_NO_TLSv1_3),
        inv("DTLSv1", SSL_OP_NO_DTLSv1),
        inv("DTLSv1.2", SSL_OP_NO_DTLSv1_2),
    ]
}

/// `Options`'s names (`ssl_option_list`).
fn option_list() -> [Flag; 26] {
    [
        inv("SessionTicket", SSL_OP_NO_TICKET),
        inv("EmptyFragments", SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS),
        both_flag("Bugs", SSL_OP_ALL),
        inv("Compression", SSL_OP_NO_COMPRESSION),
        srv("ServerPreference", SSL_OP_CIPHER_SERVER_PREFERENCE),
        srv(
            "NoResumptionOnRenegotiation",
            SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
        ),
        srv("DHSingle", op(SSL_OP_SINGLE_DH_USE)),
        srv("ECDHSingle", op(SSL_OP_SINGLE_ECDH_USE)),
        both_flag(
            "UnsafeLegacyRenegotiation",
            SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
        ),
        both_flag("UnsafeLegacyServerConnect", SSL_OP_LEGACY_SERVER_CONNECT),
        both_flag("ClientRenegotiation", SSL_OP_ALLOW_CLIENT_RENEGOTIATION),
        inv("EncryptThenMac", SSL_OP_NO_ENCRYPT_THEN_MAC),
        both_flag("NoRenegotiation", SSL_OP_NO_RENEGOTIATION),
        both_flag("AllowNoDHEKEX", SSL_OP_ALLOW_NO_DHE_KEX),
        both_flag("PreferNoDHEKEX", SSL_OP_PREFER_NO_DHE_KEX),
        both_flag("PrioritizeChaCha", SSL_OP_PRIORITIZE_CHACHA),
        both_flag("MiddleboxCompat", SSL_OP_ENABLE_MIDDLEBOX_COMPAT),
        inv("AntiReplay", SSL_OP_NO_ANTI_REPLAY),
        inv("ExtendedMasterSecret", SSL_OP_NO_EXTENDED_MASTER_SECRET),
        inv("CANames", SSL_OP_DISABLE_TLSEXT_CA_NAMES),
        both_flag("KTLS", SSL_OP_ENABLE_KTLS),
        Flag {
            name: "StrictCertCheck",
            flags: TFLAG_CERT | both(),
            value: u64::from(SSL_CERT_FLAG_TLS_STRICT),
        },
        inv(
            "TxCertificateCompression",
            SSL_OP_NO_TX_CERTIFICATE_COMPRESSION,
        ),
        inv(
            "RxCertificateCompression",
            SSL_OP_NO_RX_CERTIFICATE_COMPRESSION,
        ),
        both_flag(
            "KTLSTxZerocopySendfile",
            SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE,
        ),
        both_flag("IgnoreUnexpectedEOF", SSL_OP_IGNORE_UNEXPECTED_EOF),
    ]
}

/// `VerifyMode`'s names (`ssl_vfy_list`).
fn verify_list() -> [Flag; 6] {
    let (c, s) = (SSL_CONF_FLAG_CLIENT, SSL_CONF_FLAG_SERVER);
    [
        vfy("Peer", c, SSL_VERIFY_PEER),
        vfy("Request", s, SSL_VERIFY_PEER),
        vfy(
            "Require",
            s,
            SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        ),
        vfy("Once", s, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE),
        vfy(
            "RequestPostHandshake",
            s,
            SSL_VERIFY_PEER | SSL_VERIFY_POST_HANDSHAKE,
        ),
        vfy(
            "RequirePostHandshake",
            s,
            SSL_VERIFY_PEER | SSL_VERIFY_POST_HANDSHAKE | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        ),
    ]
}

/// What a command does.
#[derive(Clone, Copy)]
enum Cmd {
    /// A switch (`SSL_CONF_TYPE_NONE`): an option set or cleared (`ssl_cmd_switches`).
    Switch(u64, c_uint),
    SignatureAlgorithms,
    ClientSignatureAlgorithms,
    Groups,
    EcdhParameters,
    CipherString,
    Ciphersuites,
    Protocol,
    MinProtocol,
    MaxProtocol,
    Options,
    VerifyMode,
    Certificate,
    PrivateKey,
    ServerInfoFile,
    /// The chain (false) or verification (true) store, with a file, directory, or store.
    Store(bool, StoreKind),
    /// The CA names to request, from a file, directory, or store.
    RequestCa(StoreKind),
    DhParameters,
    RecordPadding,
    NumTickets,
}

/// Where certificates come from.
#[derive(Clone, Copy)]
enum StoreKind {
    File,
    Path,
    Store,
}

/// A command of the table (`ssl_conf_cmd_tbl`).
struct CmdEntry {
    cmd: Cmd,
    file: Option<&'static str>,
    cmdline: Option<&'static str>,
    flags: c_int,
    value_type: c_int,
}

/// A switch.
fn switch(name: &'static str, flags: c_int, value: u64, name_flags: c_uint) -> CmdEntry {
    CmdEntry {
        cmd: Cmd::Switch(value, name_flags),
        file: None,
        cmdline: Some(name),
        flags,
        value_type: SSL_CONF_TYPE_NONE,
    }
}

/// A command with a value.
fn valued(
    cmd: Cmd,
    file: &'static str,
    cmdline: Option<&'static str>,
    flags: c_int,
    value_type: c_int,
) -> CmdEntry {
    CmdEntry {
        cmd,
        file: Some(file),
        cmdline,
        flags,
        value_type,
    }
}

/// The commands (`ssl_conf_cmds` with `ssl_cmd_switches`), in OpenSSL's order.
fn commands() -> Vec<CmdEntry> {
    let (s, c) = (SSL_CONF_FLAG_SERVER, SSL_CONF_FLAG_CLIENT);
    let cert = SSL_CONF_FLAG_CERTIFICATE;
    let (st, file, dir, store) = (
        SSL_CONF_TYPE_STRING,
        SSL_CONF_TYPE_FILE,
        SSL_CONF_TYPE_DIR,
        SSL_CONF_TYPE_STORE,
    );
    vec![
        switch("no_ssl3", 0, SSL_OP_NO_SSLv3, 0),
        switch("no_tls1", 0, SSL_OP_NO_TLSv1, 0),
        switch("no_tls1_1", 0, SSL_OP_NO_TLSv1_1, 0),
        switch("no_tls1_2", 0, SSL_OP_NO_TLSv1_2, 0),
        switch("no_tls1_3", 0, SSL_OP_NO_TLSv1_3, 0),
        switch("bugs", 0, SSL_OP_ALL, 0),
        switch("no_comp", 0, SSL_OP_NO_COMPRESSION, 0),
        switch("comp", 0, SSL_OP_NO_COMPRESSION, TFLAG_INV),
        switch(
            "no_tx_cert_comp",
            0,
            SSL_OP_NO_TX_CERTIFICATE_COMPRESSION,
            0,
        ),
        switch(
            "tx_cert_comp",
            0,
            SSL_OP_NO_TX_CERTIFICATE_COMPRESSION,
            TFLAG_INV,
        ),
        switch(
            "no_rx_cert_comp",
            0,
            SSL_OP_NO_RX_CERTIFICATE_COMPRESSION,
            0,
        ),
        switch(
            "rx_cert_comp",
            0,
            SSL_OP_NO_RX_CERTIFICATE_COMPRESSION,
            TFLAG_INV,
        ),
        switch("ecdh_single", s, op(SSL_OP_SINGLE_ECDH_USE), 0),
        switch("no_ticket", 0, SSL_OP_NO_TICKET, 0),
        switch("serverpref", s, SSL_OP_CIPHER_SERVER_PREFERENCE, 0),
        switch(
            "legacy_renegotiation",
            0,
            SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
            0,
        ),
        switch(
            "client_renegotiation",
            s,
            SSL_OP_ALLOW_CLIENT_RENEGOTIATION,
            0,
        ),
        switch("legacy_server_connect", c, SSL_OP_LEGACY_SERVER_CONNECT, 0),
        switch("no_renegotiation", 0, SSL_OP_NO_RENEGOTIATION, 0),
        switch(
            "no_resumption_on_reneg",
            s,
            SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
            0,
        ),
        switch(
            "no_legacy_server_connect",
            c,
            SSL_OP_LEGACY_SERVER_CONNECT,
            TFLAG_INV,
        ),
        switch("allow_no_dhe_kex", 0, SSL_OP_ALLOW_NO_DHE_KEX, 0),
        switch("prefer_no_dhe_kex", 0, SSL_OP_PREFER_NO_DHE_KEX, 0),
        switch("prioritize_chacha", s, SSL_OP_PRIORITIZE_CHACHA, 0),
        switch("strict", 0, u64::from(SSL_CERT_FLAG_TLS_STRICT), TFLAG_CERT),
        switch("no_middlebox", 0, SSL_OP_ENABLE_MIDDLEBOX_COMPAT, TFLAG_INV),
        switch("anti_replay", s, SSL_OP_NO_ANTI_REPLAY, TFLAG_INV),
        switch("no_anti_replay", s, SSL_OP_NO_ANTI_REPLAY, 0),
        switch("no_etm", 0, SSL_OP_NO_ENCRYPT_THEN_MAC, 0),
        switch("no_ems", 0, SSL_OP_NO_EXTENDED_MASTER_SECRET, 0),
        valued(
            Cmd::SignatureAlgorithms,
            "SignatureAlgorithms",
            Some("sigalgs"),
            0,
            st,
        ),
        valued(
            Cmd::ClientSignatureAlgorithms,
            "ClientSignatureAlgorithms",
            Some("client_sigalgs"),
            0,
            st,
        ),
        valued(Cmd::Groups, "Curves", Some("curves"), 0, st),
        valued(Cmd::Groups, "Groups", Some("groups"), 0, st),
        valued(
            Cmd::EcdhParameters,
            "ECDHParameters",
            Some("named_curve"),
            s,
            st,
        ),
        valued(Cmd::CipherString, "CipherString", Some("cipher"), 0, st),
        valued(
            Cmd::Ciphersuites,
            "Ciphersuites",
            Some("ciphersuites"),
            0,
            st,
        ),
        valued(Cmd::Protocol, "Protocol", None, 0, st),
        valued(Cmd::MinProtocol, "MinProtocol", Some("min_protocol"), 0, st),
        valued(Cmd::MaxProtocol, "MaxProtocol", Some("max_protocol"), 0, st),
        valued(Cmd::Options, "Options", None, 0, st),
        valued(Cmd::VerifyMode, "VerifyMode", None, 0, st),
        valued(Cmd::Certificate, "Certificate", Some("cert"), cert, file),
        valued(Cmd::PrivateKey, "PrivateKey", Some("key"), cert, file),
        valued(Cmd::ServerInfoFile, "ServerInfoFile", None, s | cert, file),
        valued(
            Cmd::Store(false, StoreKind::Path),
            "ChainCAPath",
            Some("chainCApath"),
            cert,
            dir,
        ),
        valued(
            Cmd::Store(false, StoreKind::File),
            "ChainCAFile",
            Some("chainCAfile"),
            cert,
            file,
        ),
        valued(
            Cmd::Store(false, StoreKind::Store),
            "ChainCAStore",
            Some("chainCAstore"),
            cert,
            store,
        ),
        valued(
            Cmd::Store(true, StoreKind::Path),
            "VerifyCAPath",
            Some("verifyCApath"),
            cert,
            dir,
        ),
        valued(
            Cmd::Store(true, StoreKind::File),
            "VerifyCAFile",
            Some("verifyCAfile"),
            cert,
            file,
        ),
        valued(
            Cmd::Store(true, StoreKind::Store),
            "VerifyCAStore",
            Some("verifyCAstore"),
            cert,
            store,
        ),
        valued(
            Cmd::RequestCa(StoreKind::File),
            "RequestCAFile",
            Some("requestCAFile"),
            cert,
            file,
        ),
        valued(
            Cmd::RequestCa(StoreKind::File),
            "ClientCAFile",
            None,
            s | cert,
            file,
        ),
        valued(
            Cmd::RequestCa(StoreKind::Path),
            "RequestCAPath",
            None,
            cert,
            dir,
        ),
        valued(
            Cmd::RequestCa(StoreKind::Path),
            "ClientCAPath",
            None,
            s | cert,
            dir,
        ),
        valued(
            Cmd::RequestCa(StoreKind::Store),
            "RequestCAStore",
            Some("requestCAStore"),
            cert,
            store,
        ),
        valued(
            Cmd::RequestCa(StoreKind::Store),
            "ClientCAStore",
            None,
            s | cert,
            store,
        ),
        valued(
            Cmd::DhParameters,
            "DHParameters",
            Some("dhparam"),
            s | cert,
            file,
        ),
        valued(
            Cmd::RecordPadding,
            "RecordPadding",
            Some("record_padding"),
            0,
            st,
        ),
        valued(Cmd::NumTickets, "NumTickets", Some("num_tickets"), s, st),
    ]
}

/// `ssl_conf_cmd_skip_prefix`: the command without its prefix (or the command line's `-`), or
/// `None` if it lacks it.
fn skip_prefix<'a>(st: &ConfState, cmd: &'a [u8]) -> Option<&'a [u8]> {
    let cmdline = st.flags & fl(SSL_CONF_FLAG_CMDLINE) != 0;
    if let Some(prefix) = &st.prefix {
        let p = prefix.as_bytes();
        if cmd.len() <= p.len() {
            return None;
        }
        let (head, rest) = cmd.split_at(p.len());
        if cmdline && head != p {
            return None;
        }
        if st.flags & fl(SSL_CONF_FLAG_FILE) != 0 && !head.eq_ignore_ascii_case(p) {
            return None;
        }
        return Some(rest);
    }
    if cmdline {
        return match cmd.split_first() {
            Some((b'-', rest)) if !rest.is_empty() => Some(rest),
            _ => None,
        };
    }
    Some(cmd)
}

/// `ssl_conf_cmd_lookup`: the command named `cmd` that the flags allow.
fn lookup(flags: c_uint, cmd: &[u8]) -> Option<CmdEntry> {
    commands().into_iter().find(|t| {
        let tfl = fl(t.flags);
        let allowed = [
            SSL_CONF_FLAG_SERVER,
            SSL_CONF_FLAG_CLIENT,
            SSL_CONF_FLAG_CERTIFICATE,
        ]
        .iter()
        .all(|&f| tfl & fl(f) == 0 || flags & fl(f) != 0);
        allowed
            && ((flags & fl(SSL_CONF_FLAG_CMDLINE) != 0
                && t.cmdline.is_some_and(|n| n.as_bytes() == cmd))
                || (flags & fl(SSL_CONF_FLAG_FILE) != 0
                    && t.file
                        .is_some_and(|n| n.as_bytes().eq_ignore_ascii_case(cmd))))
    })
}

/// `protocol_from_string`.
fn protocol_from_string(v: &[u8]) -> Option<c_int> {
    [
        (&b"None"[..], 0),
        (b"SSLv3", SSL3_VERSION),
        (b"TLSv1", TLS1_VERSION),
        (b"TLSv1.1", TLS1_1_VERSION),
        (b"TLSv1.2", TLS1_2_VERSION),
        (b"TLSv1.3", TLS1_3_VERSION),
        (b"DTLSv1", DTLS1_VERSION),
        (b"DTLSv1.2", DTLS1_2_VERSION),
    ]
    .into_iter()
    .find(|&(n, _)| n == v)
    .map(|(_, ver)| ver)
}

/// `atoi`: leading spaces, a sign, digits; `strtol`'s saturation, then `int`'s truncation.
fn atoi(s: &[u8]) -> c_int {
    let s = s.trim_ascii_start();
    let (neg, digits) = match s.split_first() {
        Some((b'-', r)) => (true, r),
        Some((b'+', r)) => (false, r),
        _ => (false, s),
    };
    let mut v: i64 = 0;
    for &d in digits.iter().take_while(|d| d.is_ascii_digit()) {
        v = v.saturating_mul(10).saturating_add(i64::from(d - b'0'));
    }
    if neg {
        v = v.saturating_neg();
    }
    let [a, b, c, d, ..] = v.to_le_bytes();
    c_int::from_le_bytes([a, b, c, d])
}

/// Runs a command's action (`cmd_*`): above 0 for success, 0 for a bad value, -2 when it
/// doesn't apply.
///
/// # Safety
/// The target's objects are live.
#[expect(clippy::too_many_lines, reason = "one arm per command")]
unsafe fn run(cc: &ConfCtx, t: Target, cmd: Cmd, value: &CStr) -> c_int {
    let v = value.as_ptr();
    let has_ctx = !t.ctx.is_null();
    let has_ssl = !t.ssl.is_null();
    match cmd {
        Cmd::Switch(value, flags) => {
            t.set_option(flags, value, true);
            1
        }
        Cmd::SignatureAlgorithms | Cmd::ClientSignatureAlgorithms | Cmd::Groups => {
            let code = match cmd {
                Cmd::SignatureAlgorithms => SSL_CTRL_SET_SIGALGS_LIST,
                Cmd::ClientSignatureAlgorithms => SSL_CTRL_SET_CLIENT_SIGALGS_LIST,
                _ => SSL_CTRL_SET_GROUPS_LIST,
            };
            let rv = if has_ssl {
                // SAFETY: the target's connection and the value.
                unsafe { rustyssl_private_SSL_ctrl(t.ssl, code, 0, v.cast_mut().cast()) }
            } else {
                // SAFETY: the target's context (NULL checks the syntax only) and the value.
                unsafe { rustyssl_private_SSL_CTX_ctrl(t.ctx, code, 0, v.cast_mut().cast()) }
            };
            c_int::from(rv > 0)
        }
        Cmd::EcdhParameters => {
            let b = value.to_bytes();
            if t.has(SSL_CONF_FLAG_FILE)
                && (b.eq_ignore_ascii_case(b"+automatic") || b.eq_ignore_ascii_case(b"automatic"))
            {
                return 1;
            }
            if t.has(SSL_CONF_FLAG_CMDLINE) && b == b"auto" {
                return 1;
            }
            if b.contains(&b':') {
                return 0;
            }
            let p = v.cast_mut().cast();
            let rv = if has_ctx {
                // SAFETY: the target's context and the value.
                unsafe { rustyssl_private_SSL_CTX_ctrl(t.ctx, SSL_CTRL_SET_GROUPS_LIST, 0, p) }
            } else if has_ssl {
                // SAFETY: the target's connection and the value.
                unsafe { rustyssl_private_SSL_ctrl(t.ssl, SSL_CTRL_SET_GROUPS_LIST, 0, p) }
            } else {
                1
            };
            c_int::from(rv > 0)
        }
        Cmd::CipherString | Cmd::Ciphersuites => {
            let suites = matches!(cmd, Cmd::Ciphersuites);
            let mut rv = 1;
            if has_ctx {
                rv = if suites {
                    // SAFETY: the target's context and the value.
                    unsafe { rustyssl_private_SSL_CTX_set_ciphersuites(t.ctx, v) }
                } else {
                    // SAFETY: as above.
                    unsafe { rustyssl_private_SSL_CTX_set_cipher_list(t.ctx, v) }
                };
            }
            if has_ssl {
                rv = if suites {
                    // SAFETY: the target's connection and the value.
                    unsafe { rustyssl_private_SSL_set_ciphersuites(t.ssl, v) }
                } else {
                    // SAFETY: as above.
                    unsafe { rustyssl_private_SSL_set_cipher_list(t.ssl, v) }
                };
            }
            c_int::from(rv > 0)
        }
        Cmd::Protocol => t.options_from(&protocol_list(), value),
        Cmd::Options => t.options_from(&option_list(), value),
        Cmd::VerifyMode => t.options_from(&verify_list(), value),
        Cmd::MinProtocol | Cmd::MaxProtocol => {
            let Some(new) = protocol_from_string(value.to_bytes()) else {
                return 0;
            };
            let min = matches!(cmd, Cmd::MinProtocol);
            let set = |method_version: c_int, lo: &mut c_int, hi: &mut c_int| {
                set_version_bound(method_version, new, if min { lo } else { hi })
            };
            if has_ctx {
                // SAFETY: the target's context.
                let Some(x) = (unsafe { ctx(t.ctx) }) else {
                    return 0;
                };
                let mut st = x.state();
                let st = &mut *st;
                set(
                    st.method.version,
                    &mut st.min_proto_version,
                    &mut st.max_proto_version,
                )
            } else if has_ssl {
                // SAFETY: the target's connection.
                let Some(x) = (unsafe { ssl(t.ssl) }) else {
                    return 0;
                };
                let mut st = x.state();
                let st = &mut *st;
                set(
                    st.method.version,
                    &mut st.min_proto_version,
                    &mut st.max_proto_version,
                )
            } else {
                0
            }
        }
        Cmd::Certificate => {
            let mut rv = 1;
            if has_ctx {
                // SAFETY: the target's context and the file name.
                rv = unsafe { rustyssl_private_SSL_CTX_use_certificate_chain_file(t.ctx, v) };
            }
            if has_ssl {
                // SAFETY: the target's connection and the file name.
                rv = unsafe { rustyssl_private_SSL_use_certificate_chain_file(t.ssl, v) };
            }
            if rv > 0 && (has_ctx || has_ssl) && t.has(SSL_CONF_FLAG_REQUIRE_PRIVATE) {
                let Some(idx) = t.with_cert(|c| c.key) else {
                    return 0;
                };
                let mut st = cc.state();
                match st.cert_filename.get_mut(idx) {
                    Some(slot) => *slot = Some(value.to_owned()),
                    None => rv = 0,
                }
            }
            c_int::from(rv > 0)
        }
        // SAFETY: the target's objects.
        Cmd::PrivateKey => unsafe { private_key(t, v) },
        Cmd::ServerInfoFile => {
            if has_ctx {
                crate::stub::unimplemented(
                    "SSL_CONF_cmd(ServerInfoFile): SSL_CTX_use_serverinfo_file",
                );
            }
            1
        }
        // SAFETY: the target's objects.
        Cmd::Store(verify, kind) => unsafe { do_store(t, verify, kind, v) },
        Cmd::RequestCa(kind) => {
            let names = {
                let mut st = cc.state();
                if st.canames.is_null() {
                    // SAFETY: no preconditions.
                    st.canames = unsafe { OPENSSL_sk_new_null() }.cast();
                }
                st.canames
            };
            if names.is_null() {
                return 0;
            }
            // The configuration's own list (used by one thread at a time), and the value.
            match kind {
                // SAFETY: as above.
                StoreKind::File => unsafe {
                    rustyssl_private_SSL_add_file_cert_subjects_to_stack(names, v)
                },
                // SAFETY: as above.
                StoreKind::Path => unsafe {
                    rustyssl_private_SSL_add_dir_cert_subjects_to_stack(names, v)
                },
                // SAFETY: as above.
                StoreKind::Store => unsafe {
                    rustyssl_private_SSL_add_store_cert_subjects_to_stack(names, v)
                },
            }
        }
        // SAFETY: the target's objects.
        Cmd::DhParameters => unsafe { dh_parameters(t, v) },
        Cmd::RecordPadding => {
            let b = value.to_bytes();
            let (first, second) = match b.iter().position(|&c| c == b',') {
                Some(i) => {
                    let (a, rest) = b.split_at(i);
                    (a, Some(rest.get(1..).unwrap_or_default()))
                }
                None => (b, None),
            };
            let mut hs: c_ulong = 0;
            if let Some(s2) = second
                && (s2.is_empty() || !strtoul(s2, &mut hs))
            {
                return 0;
            }
            let mut block: c_ulong = 0;
            if !strtoul(first, &mut block) {
                return 0;
            }
            if second.is_none() {
                hs = block;
            }
            let (Ok(block), Ok(hs)) = (usize::try_from(block), usize::try_from(hs)) else {
                return 0;
            };
            let mut rv = 0;
            if has_ctx {
                // No QUIC methods exist yet, so a context is never a QUIC one.
                // SAFETY: the target's context.
                rv = unsafe { rustyssl_private_SSL_CTX_set_block_padding_ex(t.ctx, block, hs) };
            }
            if has_ssl {
                // SAFETY: the target's connection.
                rv = if unsafe { rustyssl_private_SSL_is_quic(t.ssl) } != 0 {
                    1
                } else {
                    // SAFETY: as above.
                    unsafe { rustyssl_private_SSL_set_block_padding_ex(t.ssl, block, hs) }
                };
            }
            rv
        }
        Cmd::NumTickets => {
            let n = atoi(value.to_bytes());
            let Ok(n) = usize::try_from(n) else { return 0 };
            let mut rv = 0;
            if has_ctx {
                // SAFETY: the target's context.
                rv =
                    unsafe { super::accessors::rustyssl_private_SSL_CTX_set_num_tickets(t.ctx, n) };
            }
            if has_ssl {
                // SAFETY: the target's connection.
                rv = unsafe { super::accessors::rustyssl_private_SSL_set_num_tickets(t.ssl, n) };
            }
            rv
        }
    }
}

/// `OPENSSL_strtoul` with base 0 over `s`.
fn strtoul(s: &[u8], out: &mut c_ulong) -> bool {
    let Ok(c) = CString::new(s) else { return false };
    let mut end: *mut c_char = ptr::null_mut();
    // SAFETY: a C string and our slots.
    unsafe { OPENSSL_strtoul(c.as_ptr(), &raw mut end, 0, out) != 0 }
}

/// `cmd_PrivateKey`.
///
/// # Safety
/// The target's objects are live; `v` a C string.
unsafe fn private_key(t: Target, v: *const c_char) -> c_int {
    if !t.has(SSL_CONF_FLAG_CERTIFICATE) {
        return -2;
    }
    let mut rv = 1;
    if !t.ctx.is_null() {
        // SAFETY: the caller's guarantee.
        rv = unsafe { rustyssl_private_SSL_CTX_use_PrivateKey_file(t.ctx, v, SSL_FILETYPE_PEM) };
    }
    if !t.ssl.is_null() {
        // SAFETY: as above.
        rv = unsafe { rustyssl_private_SSL_use_PrivateKey_file(t.ssl, v, SSL_FILETYPE_PEM) };
    }
    c_int::from(rv > 0)
}

/// `do_store`: loads into the target's chain or verification store, making it if needed.
///
/// # Safety
/// The target's objects are live; `v` a C string.
unsafe fn do_store(t: Target, verify: bool, kind: StoreKind, v: *const c_char) -> c_int {
    if t.ctx.is_null() && t.ssl.is_null() {
        return 1;
    }
    let store = t.with_cert(|c| {
        let slot = if verify {
            &mut c.verify_store
        } else {
            &mut c.chain_store
        };
        if slot.is_null() {
            // SAFETY: no preconditions.
            *slot = unsafe { X509_STORE_new() };
        }
        // A reference of our own, so the store outlives the load with no lock held.
        // SAFETY: the configuration's store, or NULL (which fails).
        if !slot.is_null() && unsafe { X509_STORE_up_ref(*slot) } != 0 {
            *slot
        } else {
            ptr::null_mut::<X509_STORE>()
        }
    });
    let Some(store) = store.filter(|s| !s.is_null()) else {
        return 0;
    };
    let (libctx, propq) = t.libctx();
    let pq = propq.as_ref().map_or(ptr::null(), |p| p.as_ptr());
    // The store (a reference held), the value, the context's library context.
    let ok = match kind {
        // SAFETY: as above.
        StoreKind::File => unsafe { X509_STORE_load_file_ex(store, v, libctx, pq) },
        // SAFETY: as above.
        StoreKind::Path => unsafe { X509_STORE_load_path(store, v) },
        // SAFETY: as above.
        StoreKind::Store => unsafe { X509_STORE_load_store_ex(store, v, libctx, pq) },
    };
    // SAFETY: the reference taken above.
    unsafe { X509_STORE_free(store) };
    c_int::from(ok != 0)
}

/// `cmd_DHParameters`: DH parameters from a PEM file for the target.
///
/// # Safety
/// The target's objects are live; `v` a C string.
unsafe fn dh_parameters(t: Target, v: *const c_char) -> c_int {
    if t.ctx.is_null() && t.ssl.is_null() {
        return 1;
    }
    // SAFETY: no preconditions.
    let meth = unsafe { BIO_s_file() };
    // SAFETY: the built-in method.
    let input = unsafe { BIO_new(meth) };
    if input.is_null() {
        return 0;
    }
    let mode = c_long::from(BIO_CLOSE | BIO_FP_READ);
    // SAFETY: our BIO and the file name (`BIO_read_filename`).
    if unsafe { BIO_ctrl(input, BIO_C_SET_FILENAME, mode, v.cast_mut().cast()) } <= 0 {
        // SAFETY: as above.
        unsafe { BIO_free(input) };
        return 0;
    }
    let (libctx, propq) = t.libctx();
    let pq = propq.as_ref().map_or(ptr::null(), |p| p.as_ptr());
    let mut dh: *mut EVP_PKEY = ptr::null_mut();
    // SAFETY: our slot, static names, the context's library context.
    let dctx = unsafe {
        OSSL_DECODER_CTX_new_for_pkey(
            &raw mut dh,
            c"PEM".as_ptr(),
            ptr::null(),
            c"DH".as_ptr(),
            OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
            libctx,
            pq,
        )
    };
    let mut rv = 0;
    if !dctx.is_null() {
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: the decoder and the BIO, both ours.
        while unsafe { OSSL_DECODER_from_bio(dctx, input) } == 0
            && dh.is_null()
            // SAFETY: the BIO.
            && unsafe { BIO_ctrl(input, BIO_CTRL_EOF, 0, ptr::null_mut()) } == 0
        {}
        // SAFETY: the decoder made above.
        unsafe { OSSL_DECODER_CTX_free(dctx) };
        if dh.is_null() {
            // SAFETY: the mark set above.
            unsafe { ERR_clear_last_mark() };
        } else {
            // SAFETY: as above.
            unsafe { ERR_pop_to_mark() };
            if !t.ctx.is_null() {
                // SAFETY: the target's context, given the key.
                rv = unsafe { rustyssl_private_SSL_CTX_set0_tmp_dh_pkey(t.ctx, dh) };
                if rv > 0 {
                    dh = ptr::null_mut();
                }
            }
            if !t.ssl.is_null() {
                // SAFETY: the target's connection, given the key.
                rv = unsafe { rustyssl_private_SSL_set0_tmp_dh_pkey(t.ssl, dh) };
                if rv > 0 {
                    dh = ptr::null_mut();
                }
            }
        }
    }
    // SAFETY: the key if no one took it, or NULL; our BIO.
    unsafe { EVP_PKEY_free(dh) };
    // SAFETY: as above.
    unsafe { BIO_free(input) };
    c_int::from(rv > 0)
}

/// `SSL_CONF_cmd`.
///
/// # Safety
/// The configuration's objects are live.
unsafe fn conf_cmd(cc: &ConfCtx, cmd: &CStr, value: Option<&CStr>) -> c_int {
    let (name, flags) = {
        let st = cc.state();
        (
            skip_prefix(&st, cmd.to_bytes()).map(<[u8]>::to_vec),
            st.flags,
        )
    };
    let show = flags & fl(SSL_CONF_FLAG_SHOW_ERRORS) != 0;
    let shown = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let entry = name.as_deref().and_then(|n| lookup(flags, n));
    let Some(entry) = entry else {
        if show {
            let n = name.as_deref().unwrap_or(cmd.to_bytes());
            let text = format!("cmd={}", shown(n));
            err::raise_with_text(ERR_LIB_SSL, SSL_R_UNKNOWN_CMD_NAME, "SSL_CONF_cmd", &text);
        }
        return -2;
    };
    let n = name.unwrap_or_default();
    let t = cc.target();
    if entry.value_type == SSL_CONF_TYPE_NONE {
        // SAFETY: the caller's guarantee.
        return unsafe { run(cc, t, entry.cmd, c"") };
    }
    let rv = match value {
        None => -3,
        Some(v) => {
            // SAFETY: the caller's guarantee.
            let rv = unsafe { run(cc, t, entry.cmd, v) };
            if rv > 0 {
                return 2;
            }
            if rv == -2 { -2 } else { 0 }
        }
    };
    if show {
        let text = format!(
            "cmd={}, value={}",
            shown(&n),
            value.map_or_else(|| "<EMPTY>".to_owned(), |v| shown(v.to_bytes()))
        );
        err::raise_with_text(ERR_LIB_SSL, SSL_R_BAD_VALUE, "SSL_CONF_cmd", &text);
    }
    rv
}

/// The configuration behind a handle.
///
/// # Safety
/// `c` is NULL or a live `SSL_CONF_CTX`.
unsafe fn conf<'a>(c: *const SSL_CONF_CTX) -> Option<&'a ConfCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { SSL_CONF_CTX::get(c) }
}

/// A C string argument, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a C string.
unsafe fn cstr<'a>(s: *const c_char) -> Option<&'a CStr> {
    if s.is_null() {
        None
    } else {
        // SAFETY: the caller's guarantee.
        Some(unsafe { CStr::from_ptr(s) })
    }
}

ffi_export! {
    /// A new configuration context, with no flags, prefix, or object.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_CONF_CTX_new() -> *mut SSL_CONF_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        SSL_CONF_CTX::new_handle(ConfCtx {
            state: Mutex::new(ConfState {
                flags: 0,
                prefix: None,
                ctx: ptr::null_mut(),
                ssl: ptr::null_mut(),
                target: false,
                cert_filename: Vec::new(),
                canames: ptr::null_mut(),
            }),
        })
    }
}

ffi_export! {
    /// Frees a configuration context (NULL: nothing), with any CA names it collected.
    ///
    /// # Safety
    /// `cctx` is NULL or a live configuration context, not used again.
    pub unsafe extern "C" fn rustyssl_private_SSL_CONF_CTX_free(cctx: *mut SSL_CONF_CTX)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { SSL_CONF_CTX::free(cctx) };
    }
}

ffi_export! {
    /// Adds `SSL_CONF_FLAG_*` flags; returns the flags now set.
    ///
    /// # Safety
    /// `cctx` is NULL or a live configuration context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CONF_CTX_set_flags(cctx: *mut SSL_CONF_CTX, flags: c_uint) -> c_uint
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { conf(cctx) }) else { return 0 };
        let mut st = c.state();
        st.flags |= flags;
        st.flags
    }
}

ffi_export! {
    /// Clears `SSL_CONF_FLAG_*` flags; returns the flags still set.
    ///
    /// # Safety
    /// `cctx` is NULL or a live configuration context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CONF_CTX_clear_flags(cctx: *mut SSL_CONF_CTX, flags: c_uint) -> c_uint
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { conf(cctx) }) else { return 0 };
        let mut st = c.state();
        st.flags &= !flags;
        st.flags
    }
}

ffi_export! {
    /// Sets the prefix commands must start with (NULL: none): 1, or 0.
    ///
    /// # Safety
    /// `cctx` is NULL or a live configuration context; `pre` NULL or a C string.
    pub unsafe extern "C" fn rustyssl_private_SSL_CONF_CTX_set1_prefix(cctx: *mut SSL_CONF_CTX, pre: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { conf(cctx) }) else { return 0 };
        // SAFETY: as above.
        c.state().prefix = unsafe { cstr(pre) }.map(CStr::to_owned);
        1
    }
}

ffi_export! {
    /// Makes commands apply to a connection (NULL: to nothing, checking syntax only).
    ///
    /// # Safety
    /// `cctx` is NULL or a live configuration context; `ssl` NULL or a connection that
    /// outlives its use here.
    pub unsafe extern "C" fn rustyssl_private_SSL_CONF_CTX_set_ssl(cctx: *mut SSL_CONF_CTX, ssl: *mut SSL)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { conf(cctx) }) else { return };
        let mut st = c.state();
        st.ssl = ssl;
        st.ctx = ptr::null_mut();
        st.target = !ssl.is_null();
        st.cert_filename = if ssl.is_null() { Vec::new() } else { vec![None; SSL_PKEY_NUM] };
    }
}

ffi_export! {
    /// Makes commands apply to a context (NULL: to nothing, checking syntax only).
    ///
    /// # Safety
    /// `cctx` is NULL or a live configuration context; `ctx` NULL or a context that outlives
    /// its use here.
    pub unsafe extern "C" fn rustyssl_private_SSL_CONF_CTX_set_ssl_ctx(cctx: *mut SSL_CONF_CTX, ctx: *mut SSL_CTX)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { conf(cctx) }) else { return };
        let mut st = c.state();
        st.ctx = ctx;
        st.ssl = ptr::null_mut();
        st.target = !ctx.is_null();
        st.cert_filename = if ctx.is_null() { Vec::new() } else { vec![None; SSL_PKEY_NUM] };
    }
}

ffi_export! {
    /// Runs one command: 2 when it took the value, 1 for a switch, 0 for a bad value, -2 for
    /// an unknown command, -3 for a missing value (errors recorded with
    /// `SSL_CONF_FLAG_SHOW_ERRORS`).
    ///
    /// # Safety
    /// `cctx` is NULL or a live configuration context whose object is live; `cmd` and `value`
    /// NULL or C strings.
    pub unsafe extern "C" fn rustyssl_private_SSL_CONF_cmd(cctx: *mut SSL_CONF_CTX, cmd: *const c_char, value: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(cmd) = (unsafe { cstr(cmd) }) else {
            err::raise(ERR_LIB_SSL, SSL_R_INVALID_NULL_CMD_NAME, "SSL_CONF_cmd");
            return 0;
        };
        // SAFETY: as above.
        let Some(c) = (unsafe { conf(cctx) }) else { return 0 };
        // SAFETY: as above.
        let value = unsafe { cstr(value) };
        // SAFETY: as above.
        unsafe { conf_cmd(c, cmd, value) }
    }
}

ffi_export! {
    /// Runs the command at the front of an argument list (command-line style): the number of
    /// arguments it used (which are skipped), 0 for none or an unknown one, -1 for a bad value,
    /// -3 for a missing one.
    ///
    /// # Safety
    /// `cctx` is NULL or a live configuration context; `pargc` NULL or a count; `pargv` points
    /// to the arguments, at least `*pargc` of them (or NULL-terminated with no count).
    pub unsafe extern "C" fn rustyssl_private_SSL_CONF_cmd_argv(cctx: *mut SSL_CONF_CTX, pargc: *mut c_int, pargv: *mut *mut *mut c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's count, or NULL.
        let argc = (!pargc.is_null()).then(|| unsafe { pargc.read() });
        if argc == Some(0) {
            return 0;
        }
        if pargv.is_null() {
            return 0;
        }
        // SAFETY: the caller's argument vector.
        let argv = unsafe { pargv.read() };
        let arg = if argc.is_none_or(|n| n > 0) {
            // SAFETY: the first argument.
            unsafe { argv.read() }
        } else {
            ptr::null_mut()
        };
        if arg.is_null() {
            return 0;
        }
        let argn = if argc.is_none_or(|n| n > 1) {
            // SAFETY: the second argument's slot (the list's NULL end with no count).
            let p = unsafe { argv.add(1) };
            // SAFETY: as above.
            unsafe { p.read() }
        } else {
            ptr::null_mut()
        };
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { conf(cctx) }) else { return 0 };
        {
            let mut st = c.state();
            st.flags &= !fl(SSL_CONF_FLAG_FILE);
            st.flags |= fl(SSL_CONF_FLAG_CMDLINE);
        }
        // SAFETY: the arguments, C strings.
        let (cmd, value) = (unsafe { CStr::from_ptr(arg) }, unsafe { cstr(argn) });
        // SAFETY: the caller's guarantee.
        let rv = unsafe { conf_cmd(c, cmd, value) };
        if rv > 0 {
            let used = usize::try_from(rv).unwrap_or(0);
            // SAFETY: within the arguments (`rv` of them were there).
            let next = unsafe { argv.add(used) };
            // SAFETY: the caller's slot.
            unsafe { pargv.write(next) };
            if let Some(n) = argc {
                // SAFETY: the caller's count.
                unsafe { pargc.write(n.saturating_sub(rv)) };
            }
            return rv;
        }
        match rv {
            -2 => 0,
            0 => -1,
            _ => rv,
        }
    }
}

ffi_export! {
    /// The kind of value a command takes (`SSL_CONF_TYPE_*`), or `SSL_CONF_TYPE_UNKNOWN`.
    ///
    /// # Safety
    /// `cctx` is NULL or a live configuration context; `cmd` NULL or a C string.
    pub unsafe extern "C" fn rustyssl_private_SSL_CONF_cmd_value_type(cctx: *mut SSL_CONF_CTX, cmd: *const c_char) -> c_int
    where failure = SSL_CONF_TYPE_UNKNOWN, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let (Some(c), Some(cmd)) = (unsafe { conf(cctx) }, unsafe { cstr(cmd) }) else {
            return SSL_CONF_TYPE_UNKNOWN;
        };
        let st = c.state();
        let flags = st.flags;
        skip_prefix(&st, cmd.to_bytes())
            .and_then(|n| lookup(flags, n))
            .map_or(SSL_CONF_TYPE_UNKNOWN, |t| t.value_type)
    }
}

ffi_export! {
    /// Ends a run of commands: loads the private keys missing for certificates read with
    /// `SSL_CONF_FLAG_REQUIRE_PRIVATE`, and installs the CA names collected: 1, or 0.
    ///
    /// # Safety
    /// `cctx` is NULL or a live configuration context whose object is live.
    pub unsafe extern "C" fn rustyssl_private_SSL_CONF_CTX_finish(cctx: *mut SSL_CONF_CTX) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { conf(cctx) }) else { return 0 };
        // SAFETY: as above.
        unsafe { finish(c) }
    }
}

/// `SSL_CONF_CTX_finish`.
///
/// # Safety
/// The configuration's objects are live.
unsafe fn finish(c: &ConfCtx) -> c_int {
    let t = c.target();
    if (!t.ctx.is_null() || !t.ssl.is_null()) && t.has(SSL_CONF_FLAG_REQUIRE_PRIVATE) {
        let files = c.state().cert_filename.clone();
        for (i, f) in files.iter().enumerate() {
            let Some(f) = f else { continue };
            let missing = t
                .with_cert(|cert| cert.pkeys.get(i).is_some_and(|p| p.privatekey.is_null()))
                .unwrap_or(false);
            // SAFETY: the target's objects and the file name.
            if missing && unsafe { private_key(t, f.as_ptr()) } == 0 {
                return 0;
            }
        }
    }
    let names = core::mem::replace(&mut c.state().canames, ptr::null_mut());
    if !names.is_null() {
        if !t.ssl.is_null() {
            // SAFETY: the target's connection, given our list.
            unsafe { rustyssl_private_SSL_set0_CA_list(t.ssl, names) };
        } else if !t.ctx.is_null() {
            // SAFETY: the target's context, given our list.
            unsafe { rustyssl_private_SSL_CTX_set0_CA_list(t.ctx, names) };
        } else {
            // SAFETY: our list.
            unsafe { OPENSSL_sk_pop_free(names.cast(), Some(name_free)) };
        }
    }
    1
}

/// `ssl_do_config`: applies the configuration's set `name` (`system_default` for the system
/// configuration) to a connection or a context. Returns whether it succeeded; the system
/// configuration's failures count only with configuration diagnostics on.
///
/// # Safety
/// `s` and `c` are NULL or live (one of them set).
unsafe fn do_config(s: *mut SSL, c: *mut SSL_CTX, name: Option<&CStr>, system: bool) -> bool {
    let name = name.or(system.then_some(c"system_default"));
    // SAFETY: the caller's objects.
    let (sx, cx) = (unsafe { ssl(s) }, unsafe { ctx(c) });
    if sx.is_none() && cx.is_none() {
        err::raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER, "ssl_do_config");
        return system;
    }
    let cmds = name.and_then(|n| {
        let sets = crate::conf::builtin::SSL_NAMES
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        sets.iter()
            .find(|set| set.name.as_c_str() == n)
            .map(|set| set.cmds.clone())
    });
    let Some(cmds) = cmds else {
        if !system {
            let n = name.map_or_else(|| "<NULL>".into(), CStr::to_string_lossy);
            let text = format!("name={n}");
            err::raise_with_text(
                ERR_LIB_SSL,
                SSL_R_INVALID_CONFIGURATION_NAME,
                "ssl_do_config",
                &text,
            );
        }
        return system;
    };
    // SAFETY: no preconditions.
    let cc_handle = unsafe { rustyssl_private_SSL_CONF_CTX_new() };
    // SAFETY: the configuration context made above.
    let Some(cc) = (unsafe { conf(cc_handle) }) else {
        return false;
    };
    let mut flags = fl(SSL_CONF_FLAG_FILE);
    if !system {
        flags |= fl(SSL_CONF_FLAG_CERTIFICATE) | fl(SSL_CONF_FLAG_REQUIRE_PRIVATE);
    }
    let (method, libctx) = match (sx, cx) {
        (Some(x), _) => {
            // SAFETY: the configuration context and the caller's connection.
            unsafe { rustyssl_private_SSL_CONF_CTX_set_ssl(cc_handle, s) };
            let st = x.state();
            // SAFETY: the connection holds a reference to its context.
            let libctx = unsafe { super::conn::ctx_of(&st) }.map_or(ptr::null_mut(), |c| c.libctx);
            (st.method, libctx)
        }
        (None, Some(x)) => {
            // SAFETY: the configuration context and the caller's context.
            unsafe { rustyssl_private_SSL_CONF_CTX_set_ssl_ctx(cc_handle, c) };
            (x.state().method, x.libctx)
        }
        (None, None) => return system,
    };
    // SAFETY: the context's library context.
    let diagnostics = unsafe { OSSL_LIB_CTX_get_conf_diagnostics(libctx) } != 0;
    if diagnostics {
        flags |= fl(SSL_CONF_FLAG_SHOW_ERRORS);
    }
    if method.server {
        flags |= fl(SSL_CONF_FLAG_SERVER);
    }
    if method.client {
        flags |= fl(SSL_CONF_FLAG_CLIENT);
    }
    cc.state().flags |= flags;
    // SAFETY: the context's library context, the default while the commands run.
    let prev = unsafe { OSSL_LIB_CTX_set0_default(libctx) };
    let mut errors = 0u32;
    for (cmd, arg) in &cmds {
        // SAFETY: the configuration context's object is the caller's.
        if unsafe { conf_cmd(cc, cmd, Some(arg)) } <= 0 {
            errors = errors.saturating_add(1);
        }
    }
    // SAFETY: as above.
    if unsafe { finish(cc) } == 0 {
        errors = errors.saturating_add(1);
    }
    // SAFETY: the previous default.
    unsafe { OSSL_LIB_CTX_set0_default(prev) };
    // SAFETY: made above.
    unsafe { SSL_CONF_CTX::free(cc_handle) };
    errors == 0 || (system && !diagnostics)
}

/// `ssl_ctx_system_config`: the configuration's `system_default` set applied to a new context.
///
/// # Safety
/// `c` is a live context.
pub(crate) unsafe fn system_config(c: *mut SSL_CTX) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { do_config(ptr::null_mut(), c, None, true) }
}

ffi_export! {
    /// Applies the configuration's `ssl_conf` set `name` to the context (certificates and keys
    /// included): 1, or 0 (`SSL_R_INVALID_CONFIGURATION_NAME` for an unknown name).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `name` NULL or a C string.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_config(ctx: *mut SSL_CTX, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let name = unsafe { cstr(name) };
        // SAFETY: as above.
        c_int::from(unsafe { do_config(ptr::null_mut(), ctx, name, false) })
    }
}

ffi_export! {
    /// Applies the configuration's `ssl_conf` set `name` to the connection, as for a context.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `name` NULL or a C string.
    pub unsafe extern "C" fn rustyssl_private_SSL_config(s: *mut SSL, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let name = unsafe { cstr(name) };
        // SAFETY: as above.
        c_int::from(unsafe { do_config(s, ptr::null_mut(), name, false) })
    }
}
