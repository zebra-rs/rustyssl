//! The names of handshake states and alerts (`SSL_state_string`, `SSL_alert_desc_string`, ...),
//! as OpenSSL's `ssl_stat.c` spells them: applications print and compare them.

use core::ffi::{CStr, c_char, c_int};

use rustyssl_abi::*;

use super::super::conn::{Ssl, ssl};
use crate::ffi::ffi_export;

/// Whether the connection has failed (`ossl_statem_in_error`).
fn in_error(x: &Ssl) -> bool {
    let st = x.state();
    st.drv.failed || st.drv.tls.as_ref().is_some_and(|c| c.error().is_some())
}

/// `SSL_state_string_long`'s name of a state.
fn state_long(state: OSSL_HANDSHAKE_STATE) -> &'static CStr {
    match state {
        TLS_ST_CR_CERT_STATUS => c"SSLv3/TLS read certificate status",
        TLS_ST_CW_NEXT_PROTO => c"SSLv3/TLS write next proto",
        TLS_ST_SR_NEXT_PROTO => c"SSLv3/TLS read next proto",
        TLS_ST_SW_CERT_STATUS => c"SSLv3/TLS write certificate status",
        TLS_ST_BEFORE => c"before SSL initialization",
        TLS_ST_OK => c"SSL negotiation finished successfully",
        TLS_ST_CW_CLNT_HELLO => c"SSLv3/TLS write client hello",
        TLS_ST_CR_SRVR_HELLO => c"SSLv3/TLS read server hello",
        TLS_ST_CR_CERT => c"SSLv3/TLS read server certificate",
        TLS_ST_CR_COMP_CERT => c"TLSv1.3 read server compressed certificate",
        TLS_ST_CR_KEY_EXCH => c"SSLv3/TLS read server key exchange",
        TLS_ST_CR_CERT_REQ => c"SSLv3/TLS read server certificate request",
        TLS_ST_CR_SESSION_TICKET => c"SSLv3/TLS read server session ticket",
        TLS_ST_CR_SRVR_DONE => c"SSLv3/TLS read server done",
        TLS_ST_CW_CERT => c"SSLv3/TLS write client certificate",
        TLS_ST_CW_COMP_CERT => c"TLSv1.3 write client compressed certificate",
        TLS_ST_CW_KEY_EXCH => c"SSLv3/TLS write client key exchange",
        TLS_ST_CW_CERT_VRFY => c"SSLv3/TLS write certificate verify",
        TLS_ST_CW_CHANGE | TLS_ST_SW_CHANGE => c"SSLv3/TLS write change cipher spec",
        TLS_ST_CW_FINISHED | TLS_ST_SW_FINISHED => c"SSLv3/TLS write finished",
        TLS_ST_CR_CHANGE | TLS_ST_SR_CHANGE => c"SSLv3/TLS read change cipher spec",
        TLS_ST_CR_FINISHED | TLS_ST_SR_FINISHED => c"SSLv3/TLS read finished",
        TLS_ST_SR_CLNT_HELLO => c"SSLv3/TLS read client hello",
        TLS_ST_SW_HELLO_REQ => c"SSLv3/TLS write hello request",
        TLS_ST_SW_SRVR_HELLO => c"SSLv3/TLS write server hello",
        TLS_ST_SW_CERT => c"SSLv3/TLS write certificate",
        TLS_ST_SW_COMP_CERT => c"TLSv1.3 write server compressed certificate",
        TLS_ST_SW_KEY_EXCH => c"SSLv3/TLS write key exchange",
        TLS_ST_SW_CERT_REQ => c"SSLv3/TLS write certificate request",
        TLS_ST_SW_SESSION_TICKET => c"SSLv3/TLS write session ticket",
        TLS_ST_SW_SRVR_DONE => c"SSLv3/TLS write server done",
        TLS_ST_SR_CERT => c"SSLv3/TLS read client certificate",
        TLS_ST_SR_COMP_CERT => c"TLSv1.3 read client compressed certificate",
        TLS_ST_SR_KEY_EXCH => c"SSLv3/TLS read client key exchange",
        TLS_ST_SR_CERT_VRFY => c"SSLv3/TLS read certificate verify",
        DTLS_ST_CR_HELLO_VERIFY_REQUEST => c"DTLS1 read hello verify request",
        DTLS_ST_SW_HELLO_VERIFY_REQUEST => c"DTLS1 write hello verify request",
        TLS_ST_SW_ENCRYPTED_EXTENSIONS => c"TLSv1.3 write encrypted extensions",
        TLS_ST_CR_ENCRYPTED_EXTENSIONS => c"TLSv1.3 read encrypted extensions",
        TLS_ST_CR_CERT_VRFY => c"TLSv1.3 read server certificate verify",
        TLS_ST_SW_CERT_VRFY => c"TLSv1.3 write server certificate verify",
        TLS_ST_CR_HELLO_REQ => c"SSLv3/TLS read hello request",
        TLS_ST_SW_KEY_UPDATE => c"TLSv1.3 write server key update",
        TLS_ST_CW_KEY_UPDATE => c"TLSv1.3 write client key update",
        TLS_ST_SR_KEY_UPDATE => c"TLSv1.3 read client key update",
        TLS_ST_CR_KEY_UPDATE => c"TLSv1.3 read server key update",
        TLS_ST_EARLY_DATA => c"TLSv1.3 early data",
        TLS_ST_PENDING_EARLY_DATA_END => c"TLSv1.3 pending early data end",
        TLS_ST_CW_END_OF_EARLY_DATA => c"TLSv1.3 write end of early data",
        TLS_ST_SR_END_OF_EARLY_DATA => c"TLSv1.3 read end of early data",
        _ => c"unknown state",
    }
}

/// `SSL_state_string`'s abbreviation of a state.
fn state_short(state: OSSL_HANDSHAKE_STATE) -> &'static CStr {
    match state {
        TLS_ST_SR_NEXT_PROTO => c"TRNP",
        TLS_ST_SW_SESSION_TICKET => c"TWST",
        TLS_ST_SW_CERT_STATUS => c"TWCS",
        TLS_ST_CR_CERT_STATUS => c"TRCS",
        TLS_ST_CR_SESSION_TICKET => c"TRST",
        TLS_ST_CW_NEXT_PROTO => c"TWNP",
        TLS_ST_BEFORE => c"PINIT",
        TLS_ST_OK => c"SSLOK",
        TLS_ST_CW_CLNT_HELLO => c"TWCH",
        TLS_ST_CR_SRVR_HELLO => c"TRSH",
        TLS_ST_CR_CERT => c"TRSC",
        TLS_ST_CR_COMP_CERT => c"TRSCC",
        TLS_ST_CR_KEY_EXCH => c"TRSKE",
        TLS_ST_CR_CERT_REQ => c"TRCR",
        TLS_ST_CR_SRVR_DONE => c"TRSD",
        TLS_ST_CW_CERT => c"TWCC",
        TLS_ST_CW_COMP_CERT => c"TWCCC",
        TLS_ST_CW_KEY_EXCH => c"TWCKE",
        TLS_ST_CW_CERT_VRFY => c"TWCV",
        TLS_ST_SW_CHANGE | TLS_ST_CW_CHANGE => c"TWCCS",
        TLS_ST_SW_FINISHED | TLS_ST_CW_FINISHED => c"TWFIN",
        TLS_ST_SR_CHANGE | TLS_ST_CR_CHANGE => c"TRCCS",
        TLS_ST_SR_FINISHED | TLS_ST_CR_FINISHED => c"TRFIN",
        TLS_ST_SW_HELLO_REQ => c"TWHR",
        TLS_ST_SR_CLNT_HELLO => c"TRCH",
        TLS_ST_SW_SRVR_HELLO => c"TWSH",
        TLS_ST_SW_CERT => c"TWSC",
        TLS_ST_SW_COMP_CERT => c"TWSCC",
        TLS_ST_SW_KEY_EXCH => c"TWSKE",
        TLS_ST_SW_CERT_REQ => c"TWCR",
        TLS_ST_SW_SRVR_DONE => c"TWSD",
        TLS_ST_SR_CERT => c"TRCC",
        TLS_ST_SR_COMP_CERT => c"TRCCC",
        TLS_ST_SR_KEY_EXCH => c"TRCKE",
        TLS_ST_SR_CERT_VRFY => c"TRCV",
        DTLS_ST_CR_HELLO_VERIFY_REQUEST => c"DRCHV",
        DTLS_ST_SW_HELLO_VERIFY_REQUEST => c"DWCHV",
        TLS_ST_SW_ENCRYPTED_EXTENSIONS => c"TWEE",
        TLS_ST_CR_ENCRYPTED_EXTENSIONS => c"TREE",
        TLS_ST_CR_CERT_VRFY => c"TRSCV",
        TLS_ST_SW_CERT_VRFY => c"TWSCV",
        TLS_ST_CR_HELLO_REQ => c"TRHR",
        TLS_ST_SW_KEY_UPDATE => c"TWSKU",
        TLS_ST_CW_KEY_UPDATE => c"TWCKU",
        TLS_ST_SR_KEY_UPDATE => c"TRCKU",
        TLS_ST_CR_KEY_UPDATE => c"TRSKU",
        TLS_ST_EARLY_DATA => c"TED",
        TLS_ST_PENDING_EARLY_DATA_END => c"TPEDE",
        TLS_ST_CW_END_OF_EARLY_DATA => c"TWEOED",
        TLS_ST_SR_END_OF_EARLY_DATA => c"TWEOED",
        _ => c"UNKWN",
    }
}

ffi_export! {
    /// The handshake state's name ("error" once the connection failed).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_state_string_long(s: *const SSL) -> *const c_char
    where failure = c"error".as_ptr(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return c"error".as_ptr() };
        if in_error(x) {
            return c"error".as_ptr();
        }
        let state = x.state().hand_state;
        state_long(state).as_ptr()
    }
}

ffi_export! {
    /// The handshake state's abbreviation ("SSLERR" once the connection failed).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_state_string(s: *const SSL) -> *const c_char
    where failure = c"SSLERR".as_ptr(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return c"SSLERR".as_ptr() };
        if in_error(x) {
            return c"SSLERR".as_ptr();
        }
        let state = x.state().hand_state;
        state_short(state).as_ptr()
    }
}

ffi_export! {
    /// An alert's level (the value's high octet): "warning", "fatal" or "unknown".
    ///
    /// # Safety
    /// None: any value.
    pub unsafe extern "C" fn rustyssl_private_SSL_alert_type_string_long(value: c_int) -> *const c_char
    where failure = c"unknown".as_ptr(), library = ERR_LIB_SSL
    {
        let s = match value >> 8 {
                SSL3_AL_WARNING => c"warning",
                SSL3_AL_FATAL => c"fatal",
                _ => c"unknown",
        };
        s.as_ptr()
    }
}

ffi_export! {
    /// An alert's level, abbreviated: "W", "F" or "U".
    ///
    /// # Safety
    /// None: any value.
    pub unsafe extern "C" fn rustyssl_private_SSL_alert_type_string(value: c_int) -> *const c_char
    where failure = c"U".as_ptr(), library = ERR_LIB_SSL
    {
        let s = match value >> 8 {
                SSL3_AL_WARNING => c"W",
                SSL3_AL_FATAL => c"F",
                _ => c"U",
        };
        s.as_ptr()
    }
}

ffi_export! {
    /// An alert's description (the value's low octet), abbreviated ("UK" if unknown).
    ///
    /// # Safety
    /// None: any value.
    pub unsafe extern "C" fn rustyssl_private_SSL_alert_desc_string(value: c_int) -> *const c_char
    where failure = c"UK".as_ptr(), library = ERR_LIB_SSL
    {
        let s = match value & 0xff {
                SSL3_AD_CLOSE_NOTIFY => c"CN",
                SSL3_AD_UNEXPECTED_MESSAGE => c"UM",
                SSL3_AD_BAD_RECORD_MAC => c"BM",
                SSL3_AD_DECOMPRESSION_FAILURE => c"DF",
                SSL3_AD_HANDSHAKE_FAILURE => c"HF",
                SSL3_AD_NO_CERTIFICATE => c"NC",
                SSL3_AD_BAD_CERTIFICATE => c"BC",
                SSL3_AD_UNSUPPORTED_CERTIFICATE => c"UC",
                SSL3_AD_CERTIFICATE_REVOKED => c"CR",
                SSL3_AD_CERTIFICATE_EXPIRED => c"CE",
                SSL3_AD_CERTIFICATE_UNKNOWN => c"CU",
                SSL3_AD_ILLEGAL_PARAMETER => c"IP",
                TLS1_AD_DECRYPTION_FAILED => c"DC",
                TLS1_AD_RECORD_OVERFLOW => c"RO",
                TLS1_AD_UNKNOWN_CA => c"CA",
                TLS1_AD_ACCESS_DENIED => c"AD",
                TLS1_AD_DECODE_ERROR => c"DE",
                TLS1_AD_DECRYPT_ERROR => c"CY",
                TLS1_AD_EXPORT_RESTRICTION => c"ER",
                TLS1_AD_PROTOCOL_VERSION => c"PV",
                TLS1_AD_INSUFFICIENT_SECURITY => c"IS",
                TLS1_AD_INTERNAL_ERROR => c"IE",
                TLS1_AD_USER_CANCELLED => c"US",
                TLS1_AD_NO_RENEGOTIATION => c"NR",
                TLS1_AD_UNSUPPORTED_EXTENSION => c"UE",
                TLS1_AD_CERTIFICATE_UNOBTAINABLE => c"CO",
                TLS1_AD_UNRECOGNIZED_NAME => c"UN",
                TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE => c"BR",
                TLS1_AD_BAD_CERTIFICATE_HASH_VALUE => c"BH",
                TLS1_AD_UNKNOWN_PSK_IDENTITY => c"UP",
                _ => c"UK",
        };
        s.as_ptr()
    }
}

ffi_export! {
    /// An alert's description ("unknown" if OpenSSL has no name for it).
    ///
    /// # Safety
    /// None: any value.
    pub unsafe extern "C" fn rustyssl_private_SSL_alert_desc_string_long(value: c_int) -> *const c_char
    where failure = c"unknown".as_ptr(), library = ERR_LIB_SSL
    {
        let s = match value & 0xff {
                SSL3_AD_CLOSE_NOTIFY => c"close notify",
                SSL3_AD_UNEXPECTED_MESSAGE => c"unexpected message",
                SSL3_AD_BAD_RECORD_MAC => c"bad record mac",
                SSL3_AD_DECOMPRESSION_FAILURE => c"decompression failure",
                SSL3_AD_HANDSHAKE_FAILURE => c"handshake failure",
                SSL3_AD_NO_CERTIFICATE => c"no certificate",
                SSL3_AD_BAD_CERTIFICATE => c"bad certificate",
                SSL3_AD_UNSUPPORTED_CERTIFICATE => c"unsupported certificate",
                SSL3_AD_CERTIFICATE_REVOKED => c"certificate revoked",
                SSL3_AD_CERTIFICATE_EXPIRED => c"certificate expired",
                SSL3_AD_CERTIFICATE_UNKNOWN => c"certificate unknown",
                SSL3_AD_ILLEGAL_PARAMETER => c"illegal parameter",
                TLS1_AD_DECRYPTION_FAILED => c"decryption failed",
                TLS1_AD_RECORD_OVERFLOW => c"record overflow",
                TLS1_AD_UNKNOWN_CA => c"unknown CA",
                TLS1_AD_ACCESS_DENIED => c"access denied",
                TLS1_AD_DECODE_ERROR => c"decode error",
                TLS1_AD_DECRYPT_ERROR => c"decrypt error",
                TLS1_AD_EXPORT_RESTRICTION => c"export restriction",
                TLS1_AD_PROTOCOL_VERSION => c"protocol version",
                TLS1_AD_INSUFFICIENT_SECURITY => c"insufficient security",
                TLS1_AD_INTERNAL_ERROR => c"internal error",
                TLS1_AD_USER_CANCELLED => c"user canceled",
                TLS1_AD_NO_RENEGOTIATION => c"no renegotiation",
                TLS1_AD_UNSUPPORTED_EXTENSION => c"unsupported extension",
                TLS1_AD_CERTIFICATE_UNOBTAINABLE => c"certificate unobtainable",
                TLS1_AD_UNRECOGNIZED_NAME => c"unrecognized name",
                TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE => c"bad certificate status response",
                TLS1_AD_BAD_CERTIFICATE_HASH_VALUE => c"bad certificate hash value",
                TLS1_AD_UNKNOWN_PSK_IDENTITY => c"unknown PSK identity",
                TLS1_AD_NO_APPLICATION_PROTOCOL => c"no application protocol",
                _ => c"unknown",
        };
        s.as_ptr()
    }
}

/// The record layer's read state: "RB" (`SSL_ST_READ_BODY`) between a record's header and the
/// rest of it, "RH" (`SSL_ST_READ_HEADER`) otherwise, as (short, long).
fn rstate(x: &Ssl) -> (&'static CStr, &'static CStr) {
    let body = x
        .state()
        .drv
        .tls
        .as_ref()
        .is_some_and(|c| c.reading_record_body());
    if body {
        (c"RB", c"read body")
    } else {
        (c"RH", c"read header")
    }
}

ffi_export! {
    /// The record layer's read state, in words ("read header", "read body").
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_rstate_string_long(s: *const SSL) -> *const c_char
    where failure = core::ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return core::ptr::null() };
        rstate(x).1.as_ptr()
    }
}

ffi_export! {
    /// The record layer's read state, abbreviated ("RH", "RB").
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_rstate_string(s: *const SSL) -> *const c_char
    where failure = core::ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return core::ptr::null() };
        rstate(x).0.as_ptr()
    }
}
