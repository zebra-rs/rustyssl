//! Handshake messages and extensions: typed decoding and encoding (RFC 8446, RFC 5246, and
//! their extensions), strict and bounded the way OpenSSL's `PACKET` code is.
//!
//! Each parser fails with the alert and `SSL_R_*` reason OpenSSL gives for that fault, in the
//! order OpenSSL checks. Where OpenSSL interleaves checks that need the connection (a decoded
//! certificate, a negotiated algorithm, the extensions sent) with reading the octets, the
//! message is read in steps (the readers in [`cert`] and [`kx`], and the raw extension blocks
//! kept in every message), so the state machine can make its checks in the same places.
//!
//! The extension blocks of the hello messages and the rest are kept as received (`Vec<u8>` of
//! the block's contents, without its length): [`ext::split`] and [`ext::collect`] turn them into
//! extensions when the state machine reaches that point.

pub mod cert;
pub mod ext;
pub mod hello;
pub mod kx;
pub mod misc;

#[cfg(test)]
mod rfc8448;
#[cfg(test)]
mod tests;

use crate::codec::{DecodeError, Reader, Writer};
use crate::consts::handshake as ht;
use crate::error::{Error, Result};

pub use cert::{
    Certificate, CertificateEntry, CertificateReader, CertificateRequest, CertificateRequest12,
    CertificateRequest13, CertificateStatus, CertificateVerify, CompressedCertificate,
    RawPublicKey,
};
pub use hello::{ClientHello, HelloVerifyRequest, ServerHello};
pub use kx::{ClientKeyExchange, ServerKeyExchange};
pub use misc::{
    EncryptedExtensions, Finished, KeyUpdate, NewSessionTicket, NewSessionTicket12,
    NewSessionTicket13, NextProtocol,
};

/// The alerts the codec sends (`SSL_AD_*`).
pub(crate) mod ad {
    pub(crate) use rustyssl_abi::{
        SSL_AD_BAD_CERTIFICATE as BAD_CERTIFICATE, SSL_AD_DECODE_ERROR as DECODE_ERROR,
        SSL_AD_HANDSHAKE_FAILURE as HANDSHAKE_FAILURE,
        SSL_AD_ILLEGAL_PARAMETER as ILLEGAL_PARAMETER, SSL_AD_INTERNAL_ERROR as INTERNAL_ERROR,
        SSL_AD_PROTOCOL_VERSION as PROTOCOL_VERSION,
        SSL_AD_UNSUPPORTED_EXTENSION as UNSUPPORTED_EXTENSION,
    };
}

/// The reasons the codec gives (`SSL_R_*`).
pub(crate) mod r {
    pub(crate) use rustyssl_abi::{
        SSL_R_BAD_DECOMPRESSION as BAD_DECOMPRESSION, SSL_R_BAD_EXTENSION as BAD_EXTENSION,
        SSL_R_BAD_KEY_UPDATE as BAD_KEY_UPDATE, SSL_R_BAD_LENGTH as BAD_LENGTH,
        SSL_R_BAD_PACKET as BAD_PACKET, SSL_R_BAD_SRP_A_LENGTH as BAD_SRP_A_LENGTH,
        SSL_R_BAD_SRTP_MKI_VALUE as BAD_SRTP_MKI_VALUE,
        SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST as BAD_SRTP_PROTECTION_PROFILE_LIST,
        SSL_R_CERT_LENGTH_MISMATCH as CERT_LENGTH_MISMATCH,
        SSL_R_DATA_LENGTH_TOO_LONG as DATA_LENGTH_TOO_LONG,
        SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG as DH_PUBLIC_VALUE_LENGTH_IS_WRONG,
        SSL_R_EMPTY_RAW_PUBLIC_KEY as EMPTY_RAW_PUBLIC_KEY,
        SSL_R_EXTRA_DATA_IN_MESSAGE as EXTRA_DATA_IN_MESSAGE,
        SSL_R_INVALID_CONTEXT as INVALID_CONTEXT,
        SSL_R_INVALID_MAX_EARLY_DATA as INVALID_MAX_EARLY_DATA,
        SSL_R_LENGTH_MISMATCH as LENGTH_MISMATCH, SSL_R_LENGTH_TOO_SHORT as LENGTH_TOO_SHORT,
        SSL_R_MISSING_TMP_DH_KEY as MISSING_TMP_DH_KEY,
        SSL_R_MISSING_TMP_ECDH_KEY as MISSING_TMP_ECDH_KEY,
        SSL_R_RECORD_LENGTH_MISMATCH as RECORD_LENGTH_MISMATCH,
        SSL_R_RENEGOTIATION_ENCODING_ERR as RENEGOTIATION_ENCODING_ERR,
        SSL_R_SIGNATURE_ALGORITHMS_ERROR as SIGNATURE_ALGORITHMS_ERROR,
        SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH as SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH,
        SSL_R_SSL3_SESSION_ID_TOO_LONG as SSL3_SESSION_ID_TOO_LONG,
        SSL_R_UNEXPECTED_MESSAGE as UNEXPECTED_MESSAGE,
        SSL_R_UNSOLICITED_EXTENSION as UNSOLICITED_EXTENSION,
        SSL_R_UNSUPPORTED_STATUS_TYPE as UNSUPPORTED_STATUS_TYPE, SSL_R_WRONG_CURVE as WRONG_CURVE,
    };
}

/// A decoding failure turned into a specific [`Error`].
pub(crate) trait OrAlert<T> {
    /// `e` in place of a [`DecodeError`].
    fn or_alert(self, e: Error) -> Result<T>;
}

impl<T> OrAlert<T> for core::result::Result<T, DecodeError> {
    fn or_alert(self, e: Error) -> Result<T> {
        self.map_err(|_| e)
    }
}

/// Encodes with a closure into a fresh body; a vector too long for its length is an internal
/// error (the caller built something no peer could receive).
pub(crate) fn encode_with(
    f: impl FnOnce(&mut Writer) -> core::result::Result<(), crate::codec::TooLong>,
) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    f(&mut w).map_err(|_| Error::internal())?;
    Ok(w.into_bytes())
}

/// A TLS handshake message's header: its type and length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The message type.
    pub typ: u8,
    /// The body's length.
    pub len: u32,
}

/// The length of a TLS handshake header.
pub const HEADER_LEN: usize = 4;

/// The length of a DTLS handshake header.
pub const DTLS_HEADER_LEN: usize = 12;

impl Header {
    /// The header at the start of `b`, if four octets are there.
    #[must_use]
    pub fn peek(b: &[u8]) -> Option<Self> {
        let mut rd = Reader::new(b);
        let typ = rd.u8().ok()?;
        let len = rd.u24().ok()?;
        Some(Self { typ, len })
    }

    /// Writes the header.
    pub fn write(&self, w: &mut Writer) {
        w.u8(self.typ);
        w.u24(self.len);
    }
}

/// A DTLS handshake message's header (RFC 6347, section 4.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DtlsHeader {
    /// The message type.
    pub typ: u8,
    /// The whole message's length.
    pub len: u32,
    /// The message's sequence number.
    pub message_seq: u16,
    /// Where this fragment starts in the message.
    pub fragment_offset: u32,
    /// This fragment's length.
    pub fragment_length: u32,
}

impl DtlsHeader {
    /// The header at the start of `b`, if twelve octets are there.
    #[must_use]
    pub fn peek(b: &[u8]) -> Option<Self> {
        let mut rd = Reader::new(b);
        Some(Self {
            typ: rd.u8().ok()?,
            len: rd.u24().ok()?,
            message_seq: rd.u16().ok()?,
            fragment_offset: rd.u24().ok()?,
            fragment_length: rd.u24().ok()?,
        })
    }

    /// Writes the header.
    pub fn write(&self, w: &mut Writer) {
        w.u8(self.typ);
        w.u24(self.len);
        w.u16(self.message_seq);
        w.u24(self.fragment_offset);
        w.u24(self.fragment_length);
    }
}

/// A complete message with its TLS header: `typ` and `body`.
///
/// # Errors
/// The body is longer than 2^24 - 1 octets (an internal error).
pub fn frame(typ: u8, body: &[u8]) -> Result<Vec<u8>> {
    encode_with(|w| {
        w.u8(typ);
        w.vec(3, body)
    })
}

/// Splits a complete TLS message (header and body) into its type and body; the length must
/// match exactly.
///
/// # Errors
/// The header is short or its length doesn't match: `SSL_R_LENGTH_MISMATCH` with decode-error.
pub fn unframe(msg: &[u8]) -> Result<(u8, &[u8])> {
    let e = Error::decode(r::LENGTH_MISMATCH);
    let mut rd = Reader::new(msg);
    let typ = rd.u8().or_alert(e)?;
    let body = rd.vec24().or_alert(e)?;
    rd.end().or_alert(e)?;
    Ok((typ, body.rest()))
}

/// The synthetic message_hash message that replaces the first ClientHello in the transcript
/// after a HelloRetryRequest (RFC 8446, section 4.4.1): its header and the hash.
///
/// # Errors
/// Never in practice (the hash is short).
pub fn message_hash(hash: &[u8]) -> Result<Vec<u8>> {
    frame(ht::MESSAGE_HASH, hash)
}

/// What decoding a message needs to know about the connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Context {
    /// TLS 1.3 is in use (or, for a ServerHello, may be negotiated: it then may be a
    /// HelloRetryRequest).
    pub tls13: bool,
    /// The connection is DTLS.
    pub dtls: bool,
    /// Signature algorithms are in use (TLS 1.2 and later): CertificateVerify,
    /// CertificateRequest, and ServerKeyExchange carry them.
    pub sigalgs: bool,
    /// The message comes from the server (for Certificate's two forms).
    pub from_server: bool,
    /// Raw public keys are in use for this Certificate (RFC 7250).
    pub rpk: bool,
    /// For ServerKeyExchange and ClientKeyExchange: the key exchange.
    pub kx: kx::Kx,
}

/// A decoded handshake message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandshakeMessage {
    /// HelloRequest.
    HelloRequest,
    /// ClientHello.
    ClientHello(ClientHello),
    /// ServerHello or HelloRetryRequest.
    ServerHello(ServerHello),
    /// HelloVerifyRequest (DTLS).
    HelloVerifyRequest(HelloVerifyRequest),
    /// NewSessionTicket.
    NewSessionTicket(NewSessionTicket),
    /// EndOfEarlyData.
    EndOfEarlyData,
    /// EncryptedExtensions.
    EncryptedExtensions(EncryptedExtensions),
    /// Certificate with X.509 certificates.
    Certificate(Certificate),
    /// Certificate with a raw public key.
    RawPublicKey(RawPublicKey),
    /// ServerKeyExchange.
    ServerKeyExchange(ServerKeyExchange),
    /// CertificateRequest.
    CertificateRequest(CertificateRequest),
    /// ServerHelloDone.
    ServerHelloDone,
    /// CertificateVerify.
    CertificateVerify(CertificateVerify),
    /// ClientKeyExchange.
    ClientKeyExchange(ClientKeyExchange),
    /// Finished.
    Finished(Finished),
    /// CertificateStatus.
    CertificateStatus(CertificateStatus),
    /// KeyUpdate.
    KeyUpdate(KeyUpdate),
    /// CompressedCertificate.
    CompressedCertificate(CompressedCertificate),
    /// NextProtocol (NPN).
    NextProtocol(NextProtocol),
    /// The synthetic message_hash.
    MessageHash(Vec<u8>),
    /// Any other type, kept as received.
    Unknown(u8, Vec<u8>),
}

impl HandshakeMessage {
    /// Decodes a message's body of type `typ` completely (every step of the step-wise readers
    /// run in order, nothing left over where OpenSSL requires it).
    ///
    /// # Errors
    /// As for each message's parser.
    pub fn decode(typ: u8, body: &[u8], cx: &Context) -> Result<Self> {
        Ok(match typ {
            ht::HELLO_REQUEST => {
                misc::empty(body)?;
                Self::HelloRequest
            }
            ht::CLIENT_HELLO => Self::ClientHello(ClientHello::parse(body, cx.dtls)?),
            ht::SERVER_HELLO => Self::ServerHello(ServerHello::parse(body, cx.tls13)?),
            ht::HELLO_VERIFY_REQUEST => Self::HelloVerifyRequest(HelloVerifyRequest::parse(body)?),
            ht::NEW_SESSION_TICKET => {
                Self::NewSessionTicket(NewSessionTicket::parse(body, cx.tls13)?)
            }
            ht::END_OF_EARLY_DATA => {
                misc::empty(body)?;
                Self::EndOfEarlyData
            }
            ht::ENCRYPTED_EXTENSIONS => {
                Self::EncryptedExtensions(EncryptedExtensions::parse(body)?)
            }
            ht::CERTIFICATE if cx.rpk => Self::RawPublicKey(RawPublicKey::parse(body, cx.tls13)?),
            ht::CERTIFICATE => {
                Self::Certificate(Certificate::parse(body, cx.tls13, cx.from_server)?)
            }
            ht::SERVER_KEY_EXCHANGE => {
                Self::ServerKeyExchange(ServerKeyExchange::parse(body, cx.kx, cx.sigalgs)?)
            }
            ht::CERTIFICATE_REQUEST => {
                Self::CertificateRequest(CertificateRequest::parse(body, cx.tls13, cx.sigalgs)?)
            }
            ht::SERVER_HELLO_DONE => {
                misc::empty(body)?;
                Self::ServerHelloDone
            }
            ht::CERTIFICATE_VERIFY => {
                Self::CertificateVerify(CertificateVerify::parse(body, cx.sigalgs)?)
            }
            ht::CLIENT_KEY_EXCHANGE => {
                Self::ClientKeyExchange(ClientKeyExchange::parse(body, cx.kx)?)
            }
            ht::FINISHED => Self::Finished(Finished {
                verify_data: body.to_vec(),
            }),
            ht::CERTIFICATE_STATUS => Self::CertificateStatus(CertificateStatus::parse(body)?),
            ht::KEY_UPDATE => Self::KeyUpdate(KeyUpdate::parse(body)?),
            ht::COMPRESSED_CERTIFICATE => {
                let c = CompressedCertificate::parse(body)?;
                c.check()?;
                Self::CompressedCertificate(c)
            }
            ht::NEXT_PROTO => Self::NextProtocol(NextProtocol::parse(body)?),
            ht::MESSAGE_HASH => Self::MessageHash(body.to_vec()),
            t => Self::Unknown(t, body.to_vec()),
        })
    }

    /// The message's type.
    #[must_use]
    pub fn typ(&self) -> u8 {
        match self {
            Self::HelloRequest => ht::HELLO_REQUEST,
            Self::ClientHello(_) => ht::CLIENT_HELLO,
            Self::ServerHello(_) => ht::SERVER_HELLO,
            Self::HelloVerifyRequest(_) => ht::HELLO_VERIFY_REQUEST,
            Self::NewSessionTicket(_) => ht::NEW_SESSION_TICKET,
            Self::EndOfEarlyData => ht::END_OF_EARLY_DATA,
            Self::EncryptedExtensions(_) => ht::ENCRYPTED_EXTENSIONS,
            Self::Certificate(_) | Self::RawPublicKey(_) => ht::CERTIFICATE,
            Self::ServerKeyExchange(_) => ht::SERVER_KEY_EXCHANGE,
            Self::CertificateRequest(_) => ht::CERTIFICATE_REQUEST,
            Self::ServerHelloDone => ht::SERVER_HELLO_DONE,
            Self::CertificateVerify(_) => ht::CERTIFICATE_VERIFY,
            Self::ClientKeyExchange(_) => ht::CLIENT_KEY_EXCHANGE,
            Self::Finished(_) => ht::FINISHED,
            Self::CertificateStatus(_) => ht::CERTIFICATE_STATUS,
            Self::KeyUpdate(_) => ht::KEY_UPDATE,
            Self::CompressedCertificate(_) => ht::COMPRESSED_CERTIFICATE,
            Self::NextProtocol(_) => ht::NEXT_PROTO,
            Self::MessageHash(_) => ht::MESSAGE_HASH,
            Self::Unknown(t, _) => *t,
        }
    }

    /// The message's body.
    ///
    /// # Errors
    /// A vector is too long for its length (an internal error).
    pub fn encode_body(&self) -> Result<Vec<u8>> {
        match self {
            Self::HelloRequest | Self::EndOfEarlyData | Self::ServerHelloDone => Ok(Vec::new()),
            Self::ClientHello(m) => m.encode(),
            Self::ServerHello(m) => m.encode(),
            Self::HelloVerifyRequest(m) => m.encode(),
            Self::NewSessionTicket(m) => m.encode(),
            Self::EncryptedExtensions(m) => m.encode(),
            Self::Certificate(m) => m.encode(),
            Self::RawPublicKey(m) => m.encode(),
            Self::ServerKeyExchange(m) => m.encode(),
            Self::CertificateRequest(m) => m.encode(),
            Self::CertificateVerify(m) => m.encode(),
            Self::ClientKeyExchange(m) => Ok(m.body.clone()),
            Self::Finished(m) => Ok(m.verify_data.clone()),
            Self::CertificateStatus(m) => m.encode(),
            Self::KeyUpdate(m) => Ok(vec![m.request_update]),
            Self::CompressedCertificate(m) => m.encode(),
            Self::NextProtocol(m) => m.encode(),
            Self::MessageHash(h) => Ok(h.clone()),
            Self::Unknown(_, b) => Ok(b.clone()),
        }
    }

    /// The message with its TLS header.
    ///
    /// # Errors
    /// As for [`HandshakeMessage::encode_body`].
    pub fn encode(&self) -> Result<Vec<u8>> {
        frame(self.typ(), &self.encode_body()?)
    }
}
