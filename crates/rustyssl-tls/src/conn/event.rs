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
    /// `SSL_CTX_set_cookie_generate_cb` and friends (stateless and DTLS cookies): the verify
    /// callback.
    pub cookie: bool,
    /// The stateless cookie's generate callback (`SSL_CTX_set_stateless_cookie_generate_cb`).
    pub cookie_gen: bool,
    /// The ticket application data callbacks (`SSL_CTX_set_session_ticket_cb`): generate.
    pub ticket_gen: bool,
    /// See `ticket_gen`: decrypt.
    pub ticket_dec: bool,
    /// `SSL_set_session_ticket_ext_cb`.
    pub session_ticket_ext: bool,
    /// `SSL_set_session_secret_cb`.
    pub session_secret: bool,
    /// `SSL_CTX_set_record_padding_callback`.
    pub record_padding: bool,
    /// `SSL_CTX_set_allow_early_data_cb`.
    pub allow_early_data: bool,
    /// Custom extensions (`SSL_CTX_add_custom_ext`).
    pub custom_ext: bool,
    /// `SSL_CTX_set_tmp_dh_callback`.
    pub tmp_dh: bool,
    /// `SSL_CTX_set_srp_username_callback` (a server's `TLS_ext_srp_username_callback`).
    pub srp_username: bool,
    /// Whether the caller refreshes the settings when a server's renegotiation starts
    /// ([`Request::Renegotiating`]).
    pub renegotiating: bool,
    /// `SSL_CTX_set_cookie_generate_cb` (DTLS).
    pub dtls_cookie_gen: bool,
    /// `SSL_CTX_set_cookie_verify_cb` (DTLS).
    pub dtls_cookie_verify: bool,
}

/// A TLS 1.2 SRP server's parameters (RFC 5054): N, g, the salt, and B, each as
/// `BN_bn2bin` writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SrpParams {
    /// The prime N.
    pub n: Vec<u8>,
    /// The generator g.
    pub g: Vec<u8>,
    /// The salt.
    pub s: Vec<u8>,
    /// The server's public value B.
    pub b: Vec<u8>,
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
        /// The chain as received, or the raw public key's SubjectPublicKeyInfo alone.
        chain: Vec<Vec<u8>>,
        /// Whether `chain` is a raw public key (`ssl_verify_rpk`).
        rpk: bool,
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
    /// Shared addition (tls-server): removes the session with this ID from the server's cache
    /// (`SSL_CTX_remove_session`, the TLS 1.3 anti-replay check of a single-use ticket),
    /// answered with [`Answer::Allowed`]: whether it was there to remove.
    RemoveSession {
        /// The session ID.
        id: Vec<u8>,
    },
    /// The ticket key callback, whose cipher and HMAC contexts then do the ticket's
    /// cryptography (`tls_decrypt_ticket`, `construct_stateless_ticket`), answered with
    /// [`Answer::TicketKey`].
    TicketKey {
        /// Decrypting: the received ticket (the callback gets its key name and IV). Empty when
        /// encrypting.
        ticket: Vec<u8>,
        /// Encrypting: the session's encoding to seal. Empty when decrypting.
        session: crate::crypto::Secret,
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
        /// The client's handshake hash after a HelloRetryRequest (`ssl_handshake_md`), else
        /// `None`.
        md: Option<crate::crypto::HashAlg>,
    },
    /// The OCSP status callback (client: check the stapled response; server: provide one).
    Status {
        /// The responder IDs the client sent, DER each (server; `SSL_get_tlsext_status_ids`).
        ocsp_ids: Vec<Vec<u8>>,
        /// The request extensions the client sent, DER (server; empty if none).
        ocsp_exts: Vec<u8>,
    },
    /// The NPN callback (client: select; server: advertise).
    Npn {
        /// The server's protocols (client side), wire format.
        protos: Vec<u8>,
    },
    /// Whether to accept the client's early data (`allow_early_data_cb`).
    AllowEarlyData,
    /// The session_ticket extension's contents for `SSL_set_session_ticket_ext_cb`'s callback:
    /// answered [`Answer::Allowed`].
    SessionTicketExt {
        /// The extension's contents.
        data: Vec<u8>,
    },
    /// `SSL_set_session_secret_cb`'s callback (EAP-FAST): the master secret to resume with,
    /// given (on a server) the client's suites' ids; answered [`Answer::SessionSecret`].
    SessionSecret {
        /// The client's suites (server side), or `None` (client side).
        peer_ciphers: Option<Vec<u32>>,
    },
    /// A server's ticket is about to be made (`generate_ticket_cb`), for this session (the
    /// connection's while the callback runs): answered [`Answer::TicketGenerated`] with what
    /// the callback left in it, or [`Answer::Fail`].
    TicketGenerate {
        /// The session the ticket will hold.
        session: Box<super::Session>,
    },
    /// A ticket was decrypted, or couldn't be (`decrypt_ticket_cb`): answered
    /// [`Answer::TicketDecrypt`] with the callback's `SSL_TICKET_RETURN_*`.
    TicketDecrypt {
        /// The ticket's key name (at most its first 16 octets).
        keyname: Vec<u8>,
        /// The decryption's `SSL_TICKET_*` status.
        status: i32,
        /// The session in it, when it decrypted.
        session: Option<Box<crate::conn::Session>>,
    },
    /// A stateless server's application cookie for its HelloRetryRequest
    /// (`gen_stateless_cookie_cb`), answered [`Answer::Cookie`].
    StatelessCookieGen,
    /// Whether the application cookie in a returned cookie is good
    /// (`verify_stateless_cookie_cb`), answered [`Answer::Allowed`].
    StatelessCookieVerify {
        /// The application's cookie.
        cookie: Vec<u8>,
    },
    /// A DTLS server's cookie for a HelloVerifyRequest (`app_gen_cookie_cb`), answered
    /// [`Answer::Cookie`] (`None`: the callback failed).
    DtlsCookieGenerate,
    /// Whether a DTLS ClientHello's cookie is good (`app_verify_cookie_cb`), answered
    /// [`Answer::Allowed`].
    DtlsCookieVerify {
        /// The cookie.
        cookie: Vec<u8>,
    },
    /// A custom extension to add (`add_cb`) or parse (`parse_cb`).
    CustomExt {
        /// The extension's index in [`crate::conn::Config::custom_exts`].
        index: usize,
        /// The extension type.
        typ: u16,
        /// The message context (`SSL_EXT_*`).
        context: u32,
        /// The received body, for parsing; `None` to add.
        body: Option<Vec<u8>>,
        /// The certificate's index in its chain (a TLS 1.3 Certificate's entries), else 0.
        chainidx: usize,
        /// That certificate (DER) for a Certificate entry's extensions (sent or received).
        cert: Option<Vec<u8>>,
    },
    /// The DH parameters for a TLS 1.2 DHE server (`tmp_dh_callback`), at this size.
    TmpDh {
        /// The key size the callback is given.
        bits: i32,
    },
    /// A client's CT validation once the server's first flight is in (`ssl_validate_ct` with
    /// `SSL_set_ct_validation_callback`'s callback): the SCTs received (the extension's in
    /// the negotiated `scts`, the stapled OCSP response's, the leaf's) checked against the
    /// verified chain. Answered [`Answer::Continue`] when they pass, or [`Answer::Fail`] with
    /// OpenSSL's alert and reason, which stops the handshake only with `SSL_VERIFY_PEER`
    /// (shared addition, fork F).
    CtValidate,
    /// A server's renegotiation is starting (the client's new ClientHello arrived): the
    /// handshake reads the connection's settings as they are now, as OpenSSL reads them from
    /// the connection (`SSL_set_options`, `SSL_set_cipher_list`, ... since the last
    /// handshake), so the configuration is brought up to date. Answered [`Answer::Continue`].
    Renegotiating,
    /// A TLS 1.2 SRP server's username callback once a suite is chosen
    /// (`ssl_srp_server_param_with_username`), with the client's login: the callback sets the
    /// user's N, g, salt and verifier (`SSL_set_srp_server_param`), and B is made from them.
    /// Answered [`Answer::SrpUsername`].
    SrpUsername {
        /// The login the client sent (the srp extension).
        login: Vec<u8>,
    },
    /// A TLS 1.2 SRP server's ServerKeyExchange parameters (`s->srp_ctx` N, g, s and B).
    /// Answered [`Answer::SrpParams`].
    SrpServerParams,
    /// A TLS 1.2 SRP server's premaster secret from the client's A
    /// (`srp_generate_server_master_secret`). Answered [`Answer::SrpValue`].
    SrpServerSecret {
        /// A, as the ClientKeyExchange carried it.
        a: Vec<u8>,
    },
    /// A TLS 1.2 SRP client's check of the server's parameters (`srp_verify_server_param`'s
    /// verify-parameter callback, or `SRP_check_known_gN_param` without one), made after
    /// the core's own checks; the parameters become the connection's (`SSL_get_srp_N`).
    /// Answered [`Answer::SrpVerified`].
    SrpVerifyParams(SrpParams),
    /// A TLS 1.2 SRP client's A at the ServerHelloDone (`ssl_srp_calc_a_param_intern`).
    /// Answered [`Answer::SrpValue`].
    SrpClientA,
    /// A TLS 1.2 SRP client's premaster secret (`srp_generate_client_master_secret`: the
    /// password callback, then the client key). Answered [`Answer::SrpValue`], or
    /// [`Answer::Fail`] when the callback gives no password.
    SrpClientSecret,
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
    /// A callback's `SSL_TLSEXT_ERR_*` result with the alert it chose (the servername
    /// callback's `*al`, which starts as `SSL_AD_UNRECOGNIZED_NAME`).
    Tlsext {
        /// `SSL_TLSEXT_ERR_OK`, `_ALERT_WARNING`, `_ALERT_FATAL`, or `_NOACK`.
        ret: i32,
        /// The alert (`SSL_AD_*`).
        alert: i32,
    },
    /// A yes-or-no callback's verdict (the security callback, `allow_early_data_cb`).
    Allowed(bool),
    /// An application cookie, or `None` when the callback failed.
    Cookie(Option<Vec<u8>>),
    /// What the generate callback left in a ticket's session: its application data and time.
    TicketGenerated {
        /// The application data (`SSL_SESSION_set1_ticket_appdata`).
        appdata: Option<Vec<u8>>,
        /// The session's time (`SSL_SESSION_set_time_ex`), in seconds.
        time: i64,
    },
    /// The session secret callback's master secret and preferred suite's id, or `None` when it
    /// gave none.
    SessionSecret(Option<(Vec<u8>, Option<u32>)>),
    /// The ticket decryption callback's `SSL_TICKET_RETURN_*`.
    TicketDecrypt(i32),
    /// The record padding callback's padding length.
    Padding(usize),
    /// A session (lookup result, PSK session), or `None`.
    Session(Option<super::Session>),
    /// A ticket key callback's result: `1` use, `2` use and renew, `0` none, negative for a
    /// failure (also of the contexts' work: `SSL_TICKET_FATAL_ERR_OTHER`); and, after `1` or
    /// `2`, what the contexts made.
    TicketKey {
        /// The callback's return value.
        ret: i32,
        /// Decrypting: the session's encoding, or `None` when the HMAC, the length or the
        /// padding didn't check (`SSL_TICKET_NO_DECRYPT`). Encrypting: the ticket (key name,
        /// IV, encrypted session, HMAC), or `None` if the contexts failed.
        data: Option<crate::crypto::Secret>,
    },
    /// A PSK callback's result: the identity (client) and key, or nothing.
    Psk(Option<super::ExternalPsk>),
    /// The status callback's result: `1` ok, `0` reject, negative error; and the responses
    /// (server).
    Status {
        /// The callback's return value.
        ret: i32,
        /// Whether the application set any response (`resp_ex` isn't empty), which promises a
        /// status (server).
        expected: bool,
        /// The OCSP response to staple for each certificate, from the leaf, where it applies
        /// (`ossl_get_ocsp_response`; server).
        responses: Vec<Option<Vec<u8>>>,
    },
    /// The NPN choice (client) or the protocols to advertise (server), wire format; `None`
    /// for no NPN.
    Npn(Option<Vec<u8>>),
    /// A custom extension's body to add (`Some`), or skip (`None`).
    CustomExt(Option<Vec<u8>>),
    /// DH parameters (`p`, `g`, big-endian), or none.
    TmpDh(Option<(Vec<u8>, Vec<u8>)>),
    /// [`Request::SrpUsername`]'s result: `ssl_srp_server_param_with_username`'s return
    /// (`SSL_ERROR_NONE`, `SSL3_AL_FATAL`, or the callback's other value) and the alert it
    /// chose.
    SrpUsername {
        /// The return value.
        ret: i32,
        /// The alert (`*ad`).
        alert: i32,
    },
    /// [`Request::SrpServerParams`]'s parameters, `None` when one is missing.
    SrpParams(Option<SrpParams>),
    /// A computed SRP value (A, or a premaster secret), `None` when it couldn't be made.
    SrpValue(Option<Vec<u8>>),
    /// [`Request::SrpVerifyParams`]'s verdict: 1 accepted, 0 the callback refused, -1 not a
    /// known group (without a callback).
    SrpVerified(i32),
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
    /// A handshake ended: capi updates the session cache (`ssl_update_cache` with
    /// `SSL_SESS_CACHE_SERVER` or `_CLIENT`), as `tls_finish_handshake` does.
    UpdateCache {
        /// Whether this end is the server.
        server: bool,
    },
    /// A TLS 1.3 client's handshake ended: its session leaves the cache
    /// (`ssl_update_cache` is skipped; the tickets that follow are cached instead, and the
    /// session it resumed is removed: `SSL_CTX_remove_session` when not reused).
    RemoveSession,
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
    /// A TLS 1.2 client got a new ticket for a session that had an ID: the old session is out
    /// of date (it leaves a client cache and can't be resumed), and the connection's session is
    /// a new one (`tls_process_new_session_ticket`).
    SessionRenewed,
    /// The call fails with nothing recorded, and the connection carries on: a stateless server
    /// read the client's ChangeCipherSpec between its ClientHellos.
    Interrupted,
}
