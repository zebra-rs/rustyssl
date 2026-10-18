//! What [`super::Connection::step`] yields (ADR 0002): one event at a time, with the
//! connection's observable state as it was at that event.

/// Which of the application's callbacks are installed, so the core asks only for those.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one flag per OpenSSL callback"
)]
pub struct Callbacks {
    /// `SSL_CTX_set_info_callback` / `SSL_set_info_callback`.
    pub info: bool,
    /// `SSL_set_msg_callback`.
    pub msg: bool,
    /// `SSL_CTX_set_keylog_callback`.
    pub keylog: bool,
    /// `SSL_CTX_set_tlsext_servername_callback`.
    pub servername: bool,
    /// `SSL_CTX_set_client_hello_cb`.
    pub client_hello: bool,
    /// `SSL_CTX_set_cert_cb` / `SSL_set_cert_cb`.
    pub cert: bool,
    /// `SSL_CTX_set_client_cert_cb`.
    pub client_cert: bool,
    /// `SSL_CTX_set_alpn_select_cb`.
    pub alpn_select: bool,
    /// `SSL_CTX_set_next_proto_select_cb` (client) and `_advertised_cb` (server).
    pub npn: bool,
    /// `SSL_CTX_set_tlsext_status_cb`.
    pub status: bool,
    /// `SSL_CTX_set_tlsext_ticket_key_evp_cb` (or the deprecated `_cb`).
    pub ticket_key: bool,
    /// `SSL_CTX_set_session_ticket_cb`'s generate and decrypt callbacks.
    pub session_ticket: bool,
    /// `SSL_CTX_sess_set_new_cb`.
    pub new_session: bool,
    /// `SSL_CTX_sess_set_get_cb`.
    pub get_session: bool,
    /// `SSL_CTX_sess_set_remove_cb`.
    pub remove_session: bool,
    /// `SSL_CTX_set_psk_client_callback` / `_server_callback` (TLS 1.2-style).
    pub psk: bool,
    /// `SSL_CTX_set_psk_use_session_callback` / `_find_session_callback` (TLS 1.3).
    pub psk_session: bool,
    /// `SSL_CTX_set_cookie_generate_cb` and friends (stateless and DTLS cookies).
    pub cookie: bool,
    /// `SSL_CTX_set_record_padding_callback`.
    pub record_padding: bool,
    /// `SSL_CTX_set_allow_early_data_cb`.
    pub allow_early_data: bool,
    /// Custom extensions (`SSL_CTX_add_custom_ext`).
    pub custom_ext: bool,
    /// `SSL_CTX_set_tmp_dh_callback`.
    pub tmp_dh: bool,
}

/// A decision the core needs from the application (or from capi on its behalf). The core stays
/// at this point until [`super::Connection::answer`] gives a matching [`Answer`]; a callback
/// that asks to suspend (`SSL_ERROR_WANT_*`) leaves it pending, and the next step asks again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// The client hello callback, with the ClientHello available through the connection.
    ClientHello,
    /// The servername callback (server; the name received is on the connection).
    Servername,
    /// The certificate callback (`cert_cb`), on either side.
    Cert,
    /// The client certificate callback (`client_cert_cb`), when no certificate is configured.
    ClientCert,
    /// Verify the peer's chain (DER, leaf first) with the application's store and callbacks.
    Verify {
        /// The chain as received.
        chain: Vec<Vec<u8>>,
    },
    /// The ALPN selection callback, with the client's protocols (wire format).
    AlpnSelect {
        /// The offered protocols, length-prefixed.
        protos: Vec<u8>,
    },
    /// A security check (`SSL_CTX_set_security_callback`), as `ssl_security` makes it.
    Security {
        /// `SSL_SECOP_*`.
        op: i32,
        /// The security bits.
        bits: i32,
        /// The NID or other number.
        nid: i32,
        /// The item, encoded as the op needs (a cipher id, a group or scheme code point).
        other: Vec<u8>,
    },
    /// A TLS 1.3 record's padding (the record padding callback).
    RecordPadding {
        /// The record's content type.
        content_type: u8,
        /// Its length before padding.
        len: usize,
    },
    /// A server-side session lookup (`get_session_cb`) by session ID.
    GetSession {
        /// The session ID the client sent.
        id: Vec<u8>,
    },
    /// A session to store (`new_session_cb`; and the internal cache).
    NewSession,
    /// The ticket key callback: encrypt (new ticket) or decrypt (received ticket).
    TicketKey {
        /// The key name (16 octets) of a received ticket; empty to make a new one.
        name: Vec<u8>,
        /// Whether to encrypt.
        encrypt: bool,
    },
    /// The TLS 1.2-style PSK callback (client: the server's hint; server: the identity).
    Psk {
        /// The hint (client) or identity (server).
        hint_or_identity: Vec<u8>,
    },
    /// The TLS 1.3 PSK session callbacks: the client's session to offer, or the session for
    /// the server's identity.
    PskSession {
        /// The identity received (server); empty for the client.
        identity: Vec<u8>,
    },
    /// The OCSP status callback (client: check the stapled response; server: provide one).
    Status,
    /// The NPN callback (client: select; server: advertise).
    Npn {
        /// The server's protocols (client side), wire format.
        protos: Vec<u8>,
    },
    /// Whether to accept the client's early data (`allow_early_data_cb`).
    AllowEarlyData,
    /// A custom extension to add (`add_cb`) or parse (`parse_cb`).
    CustomExt {
        /// The extension type.
        typ: u16,
        /// The message context (`SSL_EXT_*`).
        context: u32,
        /// The received body, for parsing; `None` to add.
        body: Option<Vec<u8>>,
    },
    /// The DH parameters for a TLS 1.2 DHE server (`tmp_dh_callback`), at this size.
    TmpDh {
        /// The key size the callback is given.
        bits: i32,
    },
}

/// The application's answer to a [`Request`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Carry on (a callback that returned success and set its results through the API or
    /// [`super::Connection::config_mut`]).
    Continue,
    /// Fail the handshake with this alert (`SSL_AD_*`) and reason (`SSL_R_*`).
    Fail {
        /// The alert to send, or `None`.
        alert: Option<u8>,
        /// The reason recorded.
        reason: i32,
    },
    /// The verification result (`X509_V_OK`: success), and whether the handshake continues
    /// regardless (`SSL_VERIFY_NONE`, or a callback that overrode the result).
    Verified {
        /// `X509_V_*`.
        result: i64,
        /// Whether to continue.
        proceed: bool,
        /// The chain verification built (DER, leaf first), for `SSL_get0_verified_chain`.
        verified_chain: Vec<Vec<u8>>,
    },
    /// The ALPN callback's choice (`SSL_TLSEXT_ERR_OK` with this protocol), or `None` for
    /// `SSL_TLSEXT_ERR_NOACK` (no protocol, continue).
    Alpn(Option<Vec<u8>>),
    /// A security callback's verdict.
    Allowed(bool),
    /// The record padding callback's padding length.
    Padding(usize),
    /// A session (lookup result, PSK session), or `None`.
    Session(Option<super::Session>),
    /// A ticket key callback's result: `1` use, `2` use and renew, `0` none, `-1` failure;
    /// with the key name, the HMAC and cipher keys, and the IV it chose (encrypting).
    TicketKey {
        /// The callback's return value.
        ret: i32,
        /// The key name.
        name: Vec<u8>,
        /// The cipher key.
        aes_key: Vec<u8>,
        /// The HMAC key.
        hmac_key: Vec<u8>,
        /// The IV.
        iv: Vec<u8>,
    },
    /// A PSK callback's result: the identity (client) and key, or nothing.
    Psk(Option<super::ExternalPsk>),
    /// The status callback's result: `1` ok, `0` reject, negative error; and the response
    /// (server).
    Status {
        /// The callback's return value.
        ret: i32,
        /// The OCSP response to staple (server), if any.
        response: Option<Vec<u8>>,
    },
    /// The NPN choice (client) or the protocols to advertise (server), wire format; `None`
    /// for no NPN.
    Npn(Option<Vec<u8>>),
    /// A custom extension's body to add (`Some`), or skip (`None`).
    CustomExt(Option<Vec<u8>>),
    /// DH parameters (`p`, `g`, big-endian), or none.
    TmpDh(Option<(Vec<u8>, Vec<u8>)>),
}

/// What [`super::Connection::step`] reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The info callback (`SSL_CB_*`), with its value.
    Info {
        /// `where`.
        where_: i32,
        /// `ret`.
        ret: i32,
    },
    /// The message callback: a record header, handshake message, alert, ChangeCipherSpec, or
    /// TLS 1.3 inner content type, as OpenSSL reports it.
    Message {
        /// Whether it was written.
        write: bool,
        /// The version OpenSSL passes.
        version: i32,
        /// The content type (`SSL3_RT_*`, including `SSL3_RT_HEADER` and
        /// `SSL3_RT_INNER_CONTENT_TYPE`).
        content_type: i32,
        /// The octets.
        bytes: Vec<u8>,
    },
    /// A key log line (`SSL_CTX_set_keylog_callback`).
    Keylog(String),
    /// A decision to make (see [`Request`]).
    Request(Request),
    /// Output is waiting ([`super::Connection::take_output`]); the core continues after it is
    /// taken (OpenSSL writes and flushes at this point).
    Output,
    /// More input is needed ([`super::Connection::feed`]).
    NeedInput,
    /// The handshake finished (`SSL_do_handshake` returns 1).
    HandshakeDone,
    /// Application data can be read ([`super::Connection::read_app`]).
    AppData,
    /// Nothing more to do for the caller's purpose (the handshake is done and the caller isn't
    /// reading).
    Idle,
    /// The peer sent close_notify (`SSL_ERROR_ZERO_RETURN` for a reader).
    Closed,
}
