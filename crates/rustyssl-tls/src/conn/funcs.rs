//! The OpenSSL functions behind each step of the state machine, so errors carry the function
//! OpenSSL raises them from (`ERR_print_errors` prints it; `ERR_get_error_all` returns it). The
//! driver names the step's function; a helper that OpenSSL implements as a separate function
//! names itself first ([`crate::error::Error::in_func`]).

use rustyssl_abi as abi;

use crate::consts::ext as t;

/// An extension handler's kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ext {
    /// `tls_parse_ctos_*` (server) or `tls_parse_stoc_*` (client).
    Parse,
    /// `tls_construct_stoc_*` (server) or `tls_construct_ctos_*` (client).
    Construct,
    /// The finaliser (`final_*`).
    Final,
}

/// A step of the state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    /// The read transition (`ossl_statem_*_read_transition`).
    ReadTransition,
    /// Processing a message's body (`ossl_statem_*_process_message`).
    Process,
    /// The work after processing it (`ossl_statem_*_post_process_message`).
    PostProcess,
    /// The write transition (`ossl_statem_*_write_transition`).
    WriteTransition,
    /// The work before constructing a message (`ossl_statem_*_pre_work`).
    PreWork,
    /// Constructing it (`ossl_statem_*_construct_message`'s function for the state).
    Construct,
    /// The work after sending it (`ossl_statem_*_post_work`).
    PostWork,
}

/// The function OpenSSL runs for `phase` in handshake state `state` on this side.
pub(crate) fn of(server: bool, phase: Phase, state: u32) -> &'static str {
    let s = |x: abi::OSSL_HANDSHAKE_STATE| state == x;
    match (server, phase) {
        (false, Phase::ReadTransition) => "ossl_statem_client_read_transition",
        (true, Phase::ReadTransition) => "ossl_statem_server_read_transition",
        (false, Phase::WriteTransition) => "ossl_statem_client_write_transition",
        (true, Phase::WriteTransition) => "ossl_statem_server_write_transition",
        (false, Phase::PreWork) => "ossl_statem_client_pre_work",
        (true, Phase::PreWork) => "ossl_statem_server_pre_work",
        (false, Phase::PostWork) => "ossl_statem_client_post_work",
        (true, Phase::PostWork) => "ossl_statem_server_post_work",
        (false, Phase::Process) => {
            if s(abi::TLS_ST_CR_SRVR_HELLO) {
                "tls_process_server_hello"
            } else if s(abi::TLS_ST_CR_CERT) {
                "tls_process_server_certificate"
            } else if s(abi::TLS_ST_CR_COMP_CERT) {
                "tls_process_server_compressed_certificate"
            } else if s(abi::TLS_ST_CR_CERT_VRFY) {
                "tls_process_cert_verify"
            } else if s(abi::TLS_ST_CR_CERT_STATUS) {
                "tls_process_cert_status_body"
            } else if s(abi::TLS_ST_CR_KEY_EXCH) {
                "tls_process_key_exchange"
            } else if s(abi::TLS_ST_CR_CERT_REQ) {
                "tls_process_certificate_request"
            } else if s(abi::TLS_ST_CR_SRVR_DONE) {
                "tls_process_server_done"
            } else if s(abi::TLS_ST_CR_CHANGE) {
                "tls_process_change_cipher_spec"
            } else if s(abi::TLS_ST_CR_SESSION_TICKET) {
                "tls_process_new_session_ticket"
            } else if s(abi::TLS_ST_CR_FINISHED) {
                "tls_process_finished"
            } else if s(abi::TLS_ST_CR_HELLO_REQ) {
                "tls_process_hello_req"
            } else if s(abi::TLS_ST_CR_ENCRYPTED_EXTENSIONS) {
                "tls_process_encrypted_extensions"
            } else if s(abi::TLS_ST_CR_KEY_UPDATE) {
                "tls_process_key_update"
            } else {
                "ossl_statem_client_process_message"
            }
        }
        (true, Phase::Process) => {
            if s(abi::TLS_ST_SR_CLNT_HELLO) {
                "tls_process_client_hello"
            } else if s(abi::TLS_ST_SR_END_OF_EARLY_DATA) {
                "tls_process_end_of_early_data"
            } else if s(abi::TLS_ST_SR_CERT) {
                "tls_process_client_certificate"
            } else if s(abi::TLS_ST_SR_COMP_CERT) {
                "tls_process_client_compressed_certificate"
            } else if s(abi::TLS_ST_SR_KEY_EXCH) {
                "tls_process_client_key_exchange"
            } else if s(abi::TLS_ST_SR_CERT_VRFY) {
                "tls_process_cert_verify"
            } else if s(abi::TLS_ST_SR_NEXT_PROTO) {
                "tls_process_next_proto"
            } else if s(abi::TLS_ST_SR_CHANGE) {
                "tls_process_change_cipher_spec"
            } else if s(abi::TLS_ST_SR_FINISHED) {
                "tls_process_finished"
            } else if s(abi::TLS_ST_SR_KEY_UPDATE) {
                "tls_process_key_update"
            } else {
                "ossl_statem_server_process_message"
            }
        }
        (false, Phase::PostProcess) => {
            if s(abi::TLS_ST_CR_CERT) || s(abi::TLS_ST_CR_COMP_CERT) {
                "tls_post_process_server_certificate"
            } else if s(abi::TLS_ST_CR_CERT_VRFY) || s(abi::TLS_ST_CR_CERT_REQ) {
                "tls_prepare_client_certificate"
            } else {
                "ossl_statem_client_post_process_message"
            }
        }
        (true, Phase::PostProcess) => {
            if s(abi::TLS_ST_SR_CLNT_HELLO) {
                "tls_post_process_client_hello"
            } else if s(abi::TLS_ST_SR_KEY_EXCH) {
                "tls_post_process_client_key_exchange"
            } else {
                "ossl_statem_server_post_process_message"
            }
        }
        (false, Phase::Construct) => {
            if s(abi::TLS_ST_CW_CHANGE) {
                "tls_construct_change_cipher_spec"
            } else if s(abi::TLS_ST_CW_CLNT_HELLO) {
                "tls_construct_client_hello"
            } else if s(abi::TLS_ST_CW_CERT) {
                "tls_construct_client_certificate"
            } else if s(abi::TLS_ST_CW_COMP_CERT) {
                "tls_construct_client_compressed_certificate"
            } else if s(abi::TLS_ST_CW_KEY_EXCH) {
                "tls_construct_client_key_exchange"
            } else if s(abi::TLS_ST_CW_CERT_VRFY) {
                "tls_construct_cert_verify"
            } else if s(abi::TLS_ST_CW_NEXT_PROTO) {
                "tls_construct_next_proto"
            } else if s(abi::TLS_ST_CW_FINISHED) {
                "tls_construct_finished"
            } else if s(abi::TLS_ST_CW_KEY_UPDATE) {
                "tls_construct_key_update"
            } else if s(abi::TLS_ST_CW_END_OF_EARLY_DATA) {
                "tls_construct_end_of_early_data"
            } else {
                "ossl_statem_client_construct_message"
            }
        }
        (true, Phase::Construct) => {
            if s(abi::TLS_ST_SW_CHANGE) {
                "tls_construct_change_cipher_spec"
            } else if s(abi::TLS_ST_SW_SRVR_HELLO) {
                "tls_construct_server_hello"
            } else if s(abi::TLS_ST_SW_CERT) {
                "tls_construct_server_certificate"
            } else if s(abi::TLS_ST_SW_COMP_CERT) {
                "tls_construct_server_compressed_certificate"
            } else if s(abi::TLS_ST_SW_CERT_VRFY) {
                "tls_construct_cert_verify"
            } else if s(abi::TLS_ST_SW_KEY_EXCH) {
                "tls_construct_server_key_exchange"
            } else if s(abi::TLS_ST_SW_CERT_REQ) {
                "tls_construct_certificate_request"
            } else if s(abi::TLS_ST_SW_SRVR_DONE) {
                "tls_construct_server_done"
            } else if s(abi::TLS_ST_SW_SESSION_TICKET) {
                "tls_construct_new_session_ticket"
            } else if s(abi::TLS_ST_SW_CERT_STATUS) {
                "tls_construct_cert_status"
            } else if s(abi::TLS_ST_SW_FINISHED) {
                "tls_construct_finished"
            } else if s(abi::TLS_ST_SW_ENCRYPTED_EXTENSIONS) {
                "tls_construct_encrypted_extensions"
            } else if s(abi::TLS_ST_SW_KEY_UPDATE) {
                "tls_construct_key_update"
            } else {
                "ossl_statem_server_construct_message"
            }
        }
    }
}

/// The built-in handler OpenSSL runs for extension `typ` (`ext_defs` in `extensions.c`), or
/// `None` where OpenSSL has none.
pub(crate) fn ext(server: bool, kind: Ext, typ: u16) -> Option<&'static str> {
    let row: [&'static str; 5] = match typ {
        t::RENEGOTIATE => [
            "tls_parse_ctos_renegotiate",
            "tls_parse_stoc_renegotiate",
            "tls_construct_stoc_renegotiate",
            "tls_construct_ctos_renegotiate",
            "final_renegotiate",
        ],
        t::SERVER_NAME => [
            "tls_parse_ctos_server_name",
            "tls_parse_stoc_server_name",
            "tls_construct_stoc_server_name",
            "tls_construct_ctos_server_name",
            "final_server_name",
        ],
        t::MAX_FRAGMENT_LENGTH => [
            "tls_parse_ctos_maxfragmentlen",
            "tls_parse_stoc_maxfragmentlen",
            "tls_construct_stoc_maxfragmentlen",
            "tls_construct_ctos_maxfragmentlen",
            "final_maxfragmentlen",
        ],
        t::SRP => ["tls_parse_ctos_srp", "", "", "tls_construct_ctos_srp", ""],
        t::EC_POINT_FORMATS => [
            "tls_parse_ctos_ec_pt_formats",
            "tls_parse_stoc_ec_pt_formats",
            "tls_construct_stoc_ec_pt_formats",
            "tls_construct_ctos_ec_pt_formats",
            "final_ec_pt_formats",
        ],
        t::SUPPORTED_GROUPS => [
            "tls_parse_ctos_supported_groups",
            "",
            "tls_construct_stoc_supported_groups",
            "tls_construct_ctos_supported_groups",
            "",
        ],
        t::SESSION_TICKET => [
            "tls_parse_ctos_session_ticket",
            "tls_parse_stoc_session_ticket",
            "tls_construct_stoc_session_ticket",
            "tls_construct_ctos_session_ticket",
            "",
        ],
        t::STATUS_REQUEST => [
            "tls_parse_ctos_status_request",
            "tls_parse_stoc_status_request",
            "tls_construct_stoc_status_request",
            "tls_construct_ctos_status_request",
            "",
        ],
        t::NEXT_PROTO_NEG => [
            "tls_parse_ctos_npn",
            "tls_parse_stoc_npn",
            "tls_construct_stoc_next_proto_neg",
            "tls_construct_ctos_npn",
            "",
        ],
        t::ALPN => [
            "tls_parse_ctos_alpn",
            "tls_parse_stoc_alpn",
            "tls_construct_stoc_alpn",
            "tls_construct_ctos_alpn",
            "final_alpn",
        ],
        t::USE_SRTP => [
            "tls_parse_ctos_use_srtp",
            "tls_parse_stoc_use_srtp",
            "tls_construct_stoc_use_srtp",
            "tls_construct_ctos_use_srtp",
            "",
        ],
        t::ENCRYPT_THEN_MAC => [
            "tls_parse_ctos_etm",
            "tls_parse_stoc_etm",
            "tls_construct_stoc_etm",
            "tls_construct_ctos_etm",
            "",
        ],
        t::SIGNED_CERTIFICATE_TIMESTAMP => {
            ["", "tls_parse_stoc_sct", "", "tls_construct_ctos_sct", ""]
        }
        t::EXTENDED_MASTER_SECRET => [
            "tls_parse_ctos_ems",
            "tls_parse_stoc_ems",
            "tls_construct_stoc_ems",
            "tls_construct_ctos_ems",
            "final_ems",
        ],
        t::SIGNATURE_ALGORITHMS_CERT => [
            "tls_parse_ctos_sig_algs_cert",
            "tls_parse_ctos_sig_algs_cert",
            "",
            "",
            "",
        ],
        t::POST_HANDSHAKE_AUTH => [
            "tls_parse_ctos_post_handshake_auth",
            "",
            "",
            "tls_construct_ctos_post_handshake_auth",
            "",
        ],
        t::CLIENT_CERT_TYPE => [
            "tls_parse_ctos_client_cert_type",
            "tls_parse_stoc_client_cert_type",
            "tls_construct_stoc_client_cert_type",
            "tls_construct_ctos_client_cert_type",
            "",
        ],
        t::SERVER_CERT_TYPE => [
            "tls_parse_ctos_server_cert_type",
            "tls_parse_stoc_server_cert_type",
            "tls_construct_stoc_server_cert_type",
            "tls_construct_ctos_server_cert_type",
            "",
        ],
        t::SIGNATURE_ALGORITHMS => [
            "tls_parse_ctos_sig_algs",
            "tls_parse_ctos_sig_algs",
            "tls_construct_ctos_sig_algs",
            "tls_construct_ctos_sig_algs",
            "final_sig_algs",
        ],
        t::SUPPORTED_VERSIONS => [
            "",
            "tls_parse_stoc_supported_versions",
            "tls_construct_stoc_supported_versions",
            "tls_construct_ctos_supported_versions",
            "final_supported_versions",
        ],
        t::PSK_KEY_EXCHANGE_MODES => [
            "tls_parse_ctos_psk_kex_modes",
            "",
            "",
            "tls_construct_ctos_psk_kex_modes",
            "",
        ],
        t::KEY_SHARE => [
            "tls_parse_ctos_key_share",
            "tls_parse_stoc_key_share",
            "tls_construct_stoc_key_share",
            "tls_construct_ctos_key_share",
            "final_key_share",
        ],
        t::COOKIE => [
            "tls_parse_ctos_cookie",
            "tls_parse_stoc_cookie",
            "tls_construct_stoc_cookie",
            "tls_construct_ctos_cookie",
            "",
        ],
        t::COMPRESS_CERTIFICATE => [
            "tls_parse_compress_certificate",
            "tls_parse_compress_certificate",
            "tls_construct_compress_certificate",
            "tls_construct_compress_certificate",
            "",
        ],
        t::EARLY_DATA => [
            "tls_parse_ctos_early_data",
            "tls_parse_stoc_early_data",
            "tls_construct_stoc_early_data",
            "tls_construct_ctos_early_data",
            "final_early_data",
        ],
        t::CERTIFICATE_AUTHORITIES => [
            "tls_parse_certificate_authorities",
            "tls_parse_certificate_authorities",
            "tls_construct_certificate_authorities",
            "tls_construct_certificate_authorities",
            "",
        ],
        t::CRYPTOPRO_BUG => ["", "", "tls_construct_stoc_cryptopro_bug", "", ""],
        t::PADDING => ["", "", "", "tls_construct_ctos_padding", ""],
        t::PRE_SHARED_KEY => [
            "tls_parse_ctos_psk",
            "tls_parse_stoc_psk",
            "tls_construct_stoc_psk",
            "tls_construct_ctos_psk",
            "final_psk",
        ],
        _ => return None,
    };
    let i = match (kind, server) {
        (Ext::Parse, true) => 0,
        (Ext::Parse, false) => 1,
        (Ext::Construct, true) => 2,
        (Ext::Construct, false) => 3,
        (Ext::Final, _) => 4,
    };
    row.get(i).copied().filter(|f| !f.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_and_extension_handlers_name_openssls_functions() {
        assert_eq!(
            of(true, Phase::Process, abi::TLS_ST_SR_CLNT_HELLO),
            "tls_process_client_hello"
        );
        assert_eq!(
            of(false, Phase::PostProcess, abi::TLS_ST_CR_CERT),
            "tls_post_process_server_certificate"
        );
        assert_eq!(
            of(false, Phase::ReadTransition, abi::TLS_ST_CR_SRVR_HELLO),
            "ossl_statem_client_read_transition"
        );
        assert_eq!(
            of(true, Phase::Construct, abi::TLS_ST_SW_SRVR_HELLO),
            "tls_construct_server_hello"
        );
        assert_eq!(
            ext(true, Ext::Parse, t::KEY_SHARE),
            Some("tls_parse_ctos_key_share")
        );
        assert_eq!(
            ext(false, Ext::Parse, t::KEY_SHARE),
            Some("tls_parse_stoc_key_share")
        );
        assert_eq!(
            ext(false, Ext::Construct, t::SERVER_NAME),
            Some("tls_construct_ctos_server_name")
        );
        assert_eq!(ext(true, Ext::Final, t::KEY_SHARE), Some("final_key_share"));
        // No handler: the dispatcher's own name applies.
        assert_eq!(ext(true, Ext::Final, t::COOKIE), None);
        assert_eq!(ext(true, Ext::Parse, t::SUPPORTED_VERSIONS), None);
        assert_eq!(ext(true, Ext::Parse, 0xfafa), None);
    }
}
