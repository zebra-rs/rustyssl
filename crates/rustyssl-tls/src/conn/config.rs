//! What a handshake reads from the `SSL` and its `SSL_CTX`. `rustyssl-capi` builds a [`Config`]
//! when a handshake starts and updates it where OpenSSL re-reads the object mid-handshake (after
//! the servername callback switches the `SSL_CTX`, after the certificate callback, ...).

use crate::crypto::KeyId;
use crate::suites::Cipher;

/// A certificate the endpoint can present, with its key.
#[derive(Clone, Debug)]
pub struct CertKey {
    /// The leaf first, then the chain to send (DER), as `ssl_add_cert_chain` would send it
    /// (the chain built or configured; the root left out unless OpenSSL would include it).
    pub chain: Vec<Vec<u8>>,
    /// The private key.
    pub key: KeyId,
    /// OpenSSL's certificate slot (`SSL_PKEY_RSA`, `SSL_PKEY_RSA_PSS_SIGN`, `SSL_PKEY_DSA_SIGN`,
    /// `SSL_PKEY_ECC`, `SSL_PKEY_ED25519`, `SSL_PKEY_ED448`, ...; providers' key types beyond).
    pub slot: usize,
    /// The signature schemes the key can make, in OpenSSL's preference order.
    pub schemes: Vec<u16>,
    /// The leaf's public key type, for TLS 1.2 suite selection (`SSL_aRSA`, `SSL_aECDSA`, ...).
    pub auth: u32,
    /// The curve of an EC key (its group's code point), for TLS 1.2's ECDSA checks.
    pub ec_group: Option<u16>,
    /// The curve of an EC key as a NID (`ssl_get_EC_curve_nid`), or `NID_undef`.
    pub curve_nid: i32,
    /// Whether the leaf may sign (no keyUsage extension, or one with digitalSignature:
    /// `ssl_set_masks`' `ecdsa_ok` for an EC certificate).
    pub can_sign: bool,
    /// The leaf's own signature, as `X509_get_signature_info` gives it (the hash's NID and the
    /// signing key's NID), for the peer's signature_algorithms_cert restrictions; `None` when
    /// there is no certificate (a raw public key only).
    pub cert_sig: Option<(i32, i32)>,
    /// A raw public key (RFC 7250) to send instead of the certificate, when negotiated.
    pub raw_public_key: Option<Vec<u8>>,
    /// The OCSP response to staple (`SSL_set_tlsext_status_ocsp_resp`), if any.
    pub ocsp_response: Option<Vec<u8>>,
    /// The chain's failure of the security level (`ssl_security_cert_chain`'s `SSL_R_*`
    /// reason), which sending it fails with; `None` when it passes.
    pub chain_security: Option<i32>,
    /// The digests (NIDs; `NID_undef` for none) the key won't sign with
    /// (`EVP_PKEY_digestsign_supports_digest`: an RSA-PSS key's restriction, say), which
    /// rule out the signature algorithms using them.
    pub unsupported_digests: Vec<i32>,
}

/// A session to resume, or one just established (what `SSL_SESSION` holds that the handshake
/// needs; capi keeps the rest).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Session {
    /// The protocol version (`SSL3_VERSION` ... `TLS1_3_VERSION`).
    pub version: u16,
    /// The cipher's id (`SSL_CIPHER_get_id`).
    pub cipher_id: u32,
    /// The session ID (TLS 1.2), up to 32 octets.
    pub session_id: Vec<u8>,
    /// The session ID context it was made under.
    pub sid_ctx: Vec<u8>,
    /// TLS 1.2's master secret, or TLS 1.3's resumption PSK.
    pub master_key: Vec<u8>,
    /// Whether the TLS 1.2 session used the Extended Master Secret.
    pub ems: bool,
    /// The ticket to send (TLS 1.2 SessionTicket or TLS 1.3 PSK identity).
    pub ticket: Option<Vec<u8>>,
    /// TLS 1.3: the ticket's age_add.
    pub ticket_age_add: u32,
    /// TLS 1.3: the ticket's lifetime hint in seconds.
    pub ticket_lifetime_hint: u64,
    /// When the session (ticket) was received, in seconds since the epoch.
    pub time: i64,
    /// Its timeout in seconds.
    pub timeout: i64,
    /// TLS 1.3: the most early data the ticket allows.
    pub max_early_data: u32,
    /// The SNI name it was made for.
    pub hostname: Option<Vec<u8>>,
    /// The ALPN protocol it negotiated (for early data).
    pub alpn: Option<Vec<u8>>,
    /// The peer's certificate chain (DER), leaf first.
    pub peer_chain: Vec<Vec<u8>>,
    /// The peer's raw public key (its SubjectPublicKeyInfo), when it sent one.
    pub peer_rpk: Option<Vec<u8>>,
    /// The verification result recorded with it (`X509_V_OK` ...).
    pub verify_result: i64,
    /// The max_fragment_length mode it used (0: none).
    pub max_fragment_len_mode: u8,
    /// The client's TLS 1.3 key exchange modes allowed with it.
    pub ext_flags: u32,
    /// The application's data carried in its ticket (`SSL_SESSION_set1_ticket_appdata`).
    pub ticket_appdata: Option<Vec<u8>>,
}

/// An external PSK (`SSL_CTX_set_psk_use_session_callback` / `psk_find_session_cb`, or the
/// TLS 1.2-style PSK callbacks), as the callbacks gave it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalPsk {
    /// The identity.
    pub identity: Vec<u8>,
    /// The key.
    pub key: Vec<u8>,
    /// The suite's id it must be used with (TLS 1.3), or 0.
    pub cipher_id: u32,
}

/// Settings a handshake reads.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// Whether this end is the server.
    pub server: bool,
    /// The method's version (`TLS_method`: 0, `TLSv1_2_method`: `TLS1_2_VERSION`, ...).
    pub method_version: u16,
    /// `SSL_set_min_proto_version` (0: the lowest supported).
    pub min_version: u16,
    /// `SSL_set_max_proto_version` (0: the highest supported).
    pub max_version: u16,
    /// `SSL_OP_*`.
    pub options: u64,
    /// `SSL_MODE_*`.
    pub mode: u64,
    /// `SSL_VERIFY_*`.
    pub verify_mode: i32,
    /// The cipher list (`SSL_get_ciphers`: TLS 1.3 suites first).
    pub ciphers: Vec<&'static Cipher>,
    /// The groups in preference order (`SSL_set1_groups_list`), with those that get an initial
    /// key share marked (3.5's `*` syntax; the default's first of each tuple).
    pub groups: Vec<u16>,
    /// The groups a client sends key shares for in its first ClientHello.
    pub key_share_groups: Vec<u16>,
    /// The 3.5 group list's tuples (indices into `groups` where each tuple starts), for the
    /// server's selection.
    pub group_tuples: Vec<usize>,
    /// The signature schemes offered and accepted (`SSL_set1_sigalgs_list`; empty: the default).
    pub sigalgs: Vec<u16>,
    /// The schemes for client certificates (`SSL_set1_client_sigalgs_list`; empty: `sigalgs`).
    pub client_sigalgs: Vec<u16>,
    /// The security level (`SSL_set_security_level`).
    pub security_level: i32,
    /// Whether the application set its own security callback, which the core then asks
    /// through [`super::Request::Security`] instead of applying the level itself.
    pub custom_security_callback: bool,
    /// The certificates the endpoint can present.
    pub certs: Vec<CertKey>,
    /// The current certificate's index in `certs` (`SSL_set_current_cert`), if one was chosen.
    pub current_cert: Option<usize>,
    /// The server name to send (client) or the name callback's result (server).
    pub hostname: Option<Vec<u8>>,
    /// The ALPN protocols offered (client), wire format.
    pub alpn: Vec<u8>,
    /// Whether the application installed callbacks the handshake must ask (servername, ALPN
    /// select, client hello, cert, verify, NPN, PSK, sessions, tickets, custom extensions ...),
    /// one flag each (`super::Callbacks`).
    pub callbacks: super::Callbacks,
    /// A session to resume (client).
    pub session: Option<Session>,
    /// The session ID context (`SSL_set_session_id_context`).
    pub sid_ctx: Vec<u8>,
    /// TLS 1.3 tickets to send after the handshake (`SSL_set_num_tickets`; default 2).
    pub num_tickets: usize,
    /// The early data allowed (`SSL_set_max_early_data`), and the receive limit.
    pub max_early_data: u32,
    /// See `max_early_data`.
    pub recv_max_early_data: u32,
    /// `SSL_set_tlsext_max_fragment_length` (0: none).
    pub max_fragment_len_mode: u8,
    /// `SSL_set_max_send_fragment` (default 16384).
    pub max_send_fragment: usize,
    /// `SSL_set_split_send_fragment`.
    pub split_send_fragment: usize,
    /// `SSL_CTX_set_block_padding_ex`: application data and handshake (0: none).
    pub block_padding: (usize, usize),
    /// `SSL_set_max_cert_list` (default 100 KiB).
    pub max_cert_list: usize,
    /// `SSL_set_verify_depth`'s depth (-1: none), passed to the verification request.
    pub verify_depth: i32,
    /// `SSL_set_post_handshake_auth`.
    pub post_handshake_auth: bool,
    /// `SSL_set_tlsext_status_type` (client asks for OCSP).
    pub status_request: bool,
    /// `SSL_enable_ct`'s request for SCTs.
    pub request_scts: bool,
    /// The certificate compression algorithms allowed, in preference order (RFC 8879 ids).
    pub cert_compression: Vec<u16>,
    /// The certificate types allowed for the client and server certificates (RFC 7250: 0 X.509,
    /// 2 raw public key), in preference order; empty: X.509 only, no extension sent.
    pub client_cert_types: Vec<u8>,
    /// See `client_cert_types`.
    pub server_cert_types: Vec<u8>,
    /// The certificate types a TLS 1.2 server's CertificateRequest lists
    /// (`SSL_set1_client_certificate_types`, `s->cert->ctype`); `None` for OpenSSL's choice by
    /// the signature algorithms allowed.
    pub req_cert_types: Option<Vec<u8>>,
    /// The CA names to send in CertificateRequest / certificate_authorities (DER names).
    pub ca_names: Vec<Vec<u8>>,
    /// Whether a client sends the certificate_authorities extension.
    pub send_ca_names: bool,
    /// An external PSK to offer (client) or the identities a server knows, via callbacks.
    pub psk: Option<ExternalPsk>,
    /// Whether this is a QUIC connection (no middlebox compatibility mode, transport params).
    pub quic: bool,
    /// The DTLS MTU, for later.
    pub mtu: usize,
    /// The certificate flags (`SSL_CERT_FLAG_*`: the Suite B modes and strict checking).
    pub cert_flags: u32,
    /// `SSL_set_session_ticket_ext`: the client's session_ticket extension contents (`Some(None)`:
    /// set with no data, and none is sent).
    pub session_ticket_ext: Option<Option<Vec<u8>>>,
    /// The key of a stateless server's cookie HMAC (`cookie_hmac_key` of the session
    /// context).
    pub cookie_hmac_key: crate::crypto::Secret,
    /// The application's custom extensions (`SSL_CTX_add_custom_ext` and the older
    /// `_add_client_custom_ext` / `_add_server_custom_ext`), in registration order.
    pub custom_exts: Vec<CustomExt>,
    /// Whether SRP is configured (a client's `SSL_set_srp_username`, so `srp_Mask` has
    /// `SSL_kSRP`); without it SRP suites are disabled.
    pub srp: bool,
    /// A client's SRP login (`s->srp_ctx.login`, at most 255 octets), sent in the srp
    /// extension.
    pub srp_login: Option<Vec<u8>>,
    /// A client's minimum SRP prime size in bits (`s->srp_ctx.strength`, `SRP_MINIMAL_N` by
    /// default).
    pub srp_strength: i32,
    /// Whether a server can do DHE: DH parameters set (`SSL_set0_tmp_dh_pkey`), a
    /// `tmp_dh_callback`, or `SSL_set_dh_auto`.
    pub dh_tmp: bool,
    // Shared addition (tls-server): what the server's handshake reads beyond the above.
    /// The time the handshake started, in seconds since the epoch (`ossl_time_now`, which the
    /// core can't read itself): sessions' times, ticket ages, and session expiry.
    pub now: i64,
    /// `SSL_CTX_set_session_cache_mode` (`SSL_SESS_CACHE_*`; OpenSSL's default is
    /// `SSL_SESS_CACHE_SERVER`): without `SSL_SESS_CACHE_SERVER` a TLS 1.2 server sends no
    /// session ID for a new session.
    pub session_cache_mode: i64,
    /// The session timeout in seconds (`SSL_CTX_set_timeout`; 0: the method's default, 7200).
    pub session_timeout: i64,
    /// The default session ticket keys: `SSL_CTX_set_tlsext_ticket_keys`, or the random ones
    /// OpenSSL makes for every `SSL_CTX` (capi makes them the same way, once per `SSL_CTX`, and
    /// keeps them for the session context's lifetime). Used when no ticket key callback is
    /// installed ([`super::Callbacks::ticket_key`]); `None` makes tickets that can't be
    /// encrypted fail with an internal error, as a missing key would in OpenSSL.
    pub ticket_keys: Option<TicketKeys>,
    /// The PSK identity hint (`SSL_CTX_use_psk_identity_hint`), sent in a TLS 1.2 PSK
    /// ServerKeyExchange.
    pub psk_identity_hint: Option<Vec<u8>>,
    /// DH parameters (`p`, `g`, big-endian) set with `SSL_set0_tmp_dh_pkey`, for TLS 1.2's DHE.
    pub dh_params: Option<(Vec<u8>, Vec<u8>)>,
    /// `SSL_set_dh_auto`: DHE parameters chosen by the suite's strength (RFC 7919's groups).
    pub dh_auto: bool,
    /// The SRTP protection profiles (`SSL_set_tlsext_use_srtp`), in preference order.
    pub srtp_profiles: Vec<u16>,
}

/// Session ticket keys (`SSL_CTX_set_tlsext_ticket_keys`' 80 octets: the key name, the HMAC
/// key, and the AES-256 key). Tickets are AES-256-CBC with HMAC-SHA256 over the name, IV, and
/// ciphertext, as OpenSSL makes them.
#[derive(Clone, Debug, Default)]
pub struct TicketKeys {
    /// The key name (16 octets), sent at the start of each ticket.
    pub name: [u8; 16],
    /// The HMAC-SHA256 key (32 octets).
    pub hmac_key: crate::crypto::Secret,
    /// The AES-256-CBC key (32 octets).
    pub aes_key: crate::crypto::Secret,
}

/// A registered custom extension (`custom_ext_method`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomExt {
    /// The extension type.
    pub typ: u16,
    /// The contexts it applies to (`SSL_EXT_*`).
    pub context: u32,
    /// Which side registered it: `Some(true)` the server's (`_add_server_custom_ext`),
    /// `Some(false)` the client's, `None` either (`SSL_CTX_add_custom_ext`, `ENDPOINT_BOTH`).
    pub server: Option<bool>,
    /// Whether it has an add callback (the old API's extensions without one are sent empty
    /// only in a ClientHello).
    pub has_add: bool,
    /// Whether it has a parse callback (without one, a received extension is accepted
    /// unread).
    pub has_parse: bool,
}
