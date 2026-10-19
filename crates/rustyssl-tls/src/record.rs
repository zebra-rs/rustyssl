//! The TLS record layer, sans-IO: records parsed out of a byte buffer and protected or
//! unprotected (TLS 1.3's AEAD and integrity-only protection, TLS 1.0–1.2's AEADs, CBC with
//! MAC-then-encrypt or encrypt-then-MAC, and the NULL cipher), and outgoing data fragmented
//! and protected into records.
//!
//! Every check and its failure follow OpenSSL's record layer (`ssl/record/methods`): the alert
//! and the `SSL_R_*` reason of each, in the same order. MAC-then-encrypt records are checked in
//! constant time: the padding (`tls1_cbc_remove_padding_and_mac`), the MAC's extraction
//! (`ssl3_cbc_copy_mac`), and the MAC itself ([`Provider::tls_cbc_mac`]).

use rustyssl_abi as abi;
use subtle::ConstantTimeEq;

use crate::crypto::{Aead, AeadAlg, Cipher, CipherAlg, HashAlg, Provider, Secret};
use crate::error::{Cause, Error, InFunc, Result};

/// A content type, as the record header carries it (`SSL3_RT_*`).
pub type ContentType = u8;

/// The record header's length.
pub const HEADER_LEN: usize = 5;
/// The largest plaintext fragment (2^14).
pub const MAX_PLAIN: usize = 16384;
/// The most a block cipher pads (the length octet's range).
const MAX_PADDING: usize = 256;
/// How many empty records in a row OpenSSL accepts (`MAX_EMPTY_RECORDS`).
const MAX_EMPTY_RECORDS: u32 = 32;
/// The shortest SSLv2 ClientHello record (`MIN_SSL2_RECORD_LEN`).
const MIN_SSL2_RECORD_LEN: usize = 9;
/// The SSLv2 record header's length.
const SSL2_HEADER_LEN: usize = 2;
/// `SSL2_VERSION`: the version reported for an SSLv2-format record.
pub const SSL2_VERSION: u16 = 0x0002;

/// A `c_int` constant as an octet (every content type and alert fits).
fn octet(v: core::ffi::c_int) -> u8 {
    u8::try_from(v).unwrap_or(0)
}

/// A `c_int` length constant as a `usize`.
fn size(v: core::ffi::c_int) -> usize {
    usize::try_from(v).unwrap_or(0)
}

/// The content types.
pub mod content_type {
    use super::{ContentType, octet};

    /// `SSL3_RT_CHANGE_CIPHER_SPEC`.
    #[must_use]
    pub fn change_cipher_spec() -> ContentType {
        octet(rustyssl_abi::SSL3_RT_CHANGE_CIPHER_SPEC)
    }
    /// `SSL3_RT_ALERT`.
    #[must_use]
    pub fn alert() -> ContentType {
        octet(rustyssl_abi::SSL3_RT_ALERT)
    }
    /// `SSL3_RT_HANDSHAKE`.
    #[must_use]
    pub fn handshake() -> ContentType {
        octet(rustyssl_abi::SSL3_RT_HANDSHAKE)
    }
    /// `SSL3_RT_APPLICATION_DATA`.
    #[must_use]
    pub fn application_data() -> ContentType {
        octet(rustyssl_abi::SSL3_RT_APPLICATION_DATA)
    }
}

use content_type::{alert, application_data, change_cipher_spec, handshake};

/// A fatal record-layer error with OpenSSL's alert and reason.
fn fatal(alert: core::ffi::c_int, reason: core::ffi::c_int) -> Error {
    Error::alert(alert, reason)
}

/// A fatal error that sends no alert (OpenSSL's `SSL_AD_NO_ALERT`).
fn quiet(reason: core::ffi::c_int) -> Error {
    Error::quiet(reason)
}

/// The failure of a record that doesn't decrypt or authenticate.
fn bad_mac() -> Error {
    fatal(
        abi::SSL_AD_BAD_RECORD_MAC,
        abi::SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC,
    )
}

/// The record's sequence number, as the nonce and MAC take it.
fn seq_bytes(seq: u64) -> [u8; 8] {
    seq.to_be_bytes()
}

/// The next sequence number, or OpenSSL's `SSL_R_SEQUENCE_CTR_WRAPPED`.
fn next_seq(seq: &mut u64) -> Result<u64> {
    let cur = *seq;
    *seq = cur.checked_add(1).ok_or_else(|| {
        fatal(abi::SSL_AD_INTERNAL_ERROR, abi::SSL_R_SEQUENCE_CTR_WRAPPED)
            .in_func("tls_increment_sequence_ctr")
    })?;
    Ok(cur)
}

/// The record's sequence number for the MAC and nonce: DTLS's `epoch || sequence` from its
/// header when given, else the next of TLS's counter.
fn take_seq(fixed: Option<u64>, seq: &mut u64) -> Result<u64> {
    match fixed {
        Some(s) => Ok(s),
        None => next_seq(seq),
    }
}

/// `iv XOR seq`, the sequence number right-aligned (TLS 1.3, and TLS 1.2's ChaCha20-Poly1305).
fn xor_nonce(iv: &[u8], seq: u64) -> Vec<u8> {
    let s = seq_bytes(seq);
    let off = iv.len().saturating_sub(8);
    iv.iter()
        .enumerate()
        .map(|(i, &b)| {
            b ^ i
                .checked_sub(off)
                .and_then(|j| s.get(j))
                .copied()
                .unwrap_or(0)
        })
        .collect()
}

/// TLS 1.0–1.2's MAC header: sequence number, type, version, length.
fn mac_header(seq: u64, ty: ContentType, version: u16, len: usize) -> Result<[u8; 13]> {
    let mut h = [0u8; 13];
    let (s, rest) = h.split_at_mut(8);
    s.copy_from_slice(&seq_bytes(seq));
    let [v0, v1] = version.to_be_bytes();
    let [l0, l1] = u16::try_from(len)
        .map_err(|_| Error::internal())?
        .to_be_bytes();
    rest.copy_from_slice(&[ty, v0, v1, l0, l1]);
    Ok(h)
}

/// How a direction's records are protected.
pub enum Protection {
    /// None yet (the handshake's first flights).
    Null,
    /// TLS 1.3's AEAD protection (RFC 8446, section 5.2).
    Tls13 {
        /// The keyed AEAD.
        aead: Box<dyn Aead>,
        /// The static IV.
        iv: Secret,
        /// The tag's length.
        tag_len: usize,
    },
    /// TLS 1.3's integrity-only protection (RFC 9150): an HMAC tag over the nonce, the header,
    /// and the plaintext, which stays in the clear.
    Tls13Integrity {
        /// The MAC's hash.
        hash: HashAlg,
        /// The MAC key (the traffic key).
        key: Secret,
        /// The static IV (the hash's length).
        iv: Secret,
    },
    /// TLS 1.2's AEADs: GCM and CCM with an 8-octet explicit nonce after a 4-octet fixed IV
    /// (RFC 5288, RFC 6655), ChaCha20-Poly1305 with the IV XORed with the sequence number
    /// (RFC 7905).
    Aead12 {
        /// The keyed AEAD.
        aead: Box<dyn Aead>,
        /// The fixed IV (4 octets) or the whole IV (12, for ChaCha20-Poly1305).
        iv: Secret,
        /// Whether an explicit nonce goes on the wire (GCM, CCM).
        explicit: bool,
        /// The tag's length.
        tag_len: usize,
        /// The next explicit nonce to send (OpenSSL starts it at random and counts up).
        next_explicit: u64,
        /// The provider function that raises an error under a bad tag, if OpenSSL's does
        /// (GCM's and CCM's TLS mode; ChaCha20-Poly1305's raises none).
        tag_error_func: Option<&'static str>,
    },
    /// TLS 1.0–1.2's CBC (or NULL) cipher with an HMAC.
    Cbc12 {
        /// The keyed cipher (`None` for the NULL cipher).
        cipher: Option<Box<dyn Cipher>>,
        /// The block length (0 for the NULL cipher).
        block_len: usize,
        /// The MAC's hash.
        mac_hash: HashAlg,
        /// The MAC key.
        mac_key: Secret,
        /// The chaining value: the last ciphertext block so far (at first, the key block's IV,
        /// or zeros where there's none). TLS 1.0 chains each record from it; later versions
        /// also run their explicit IV through the chain, as OpenSSL does (the first block of
        /// each record is the encrypted random block, discarded when decrypting), so a cipher
        /// keeps one CBC stream per direction and is never re-initialized.
        iv: Vec<u8>,
        /// Whether each record carries its IV (TLS 1.1 and later).
        explicit_iv: bool,
        /// Encrypt-then-MAC (RFC 7366).
        etm: bool,
    },
}

impl core::fmt::Debug for Protection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Null => "Protection::Null",
            Self::Tls13 { .. } => "Protection::Tls13",
            Self::Tls13Integrity { .. } => "Protection::Tls13Integrity",
            Self::Aead12 { .. } => "Protection::Aead12",
            Self::Cbc12 { .. } => "Protection::Cbc12",
        })
    }
}

impl Protection {
    /// TLS 1.3 protection with `alg` and a traffic secret's key and IV.
    ///
    /// # Errors
    /// The provider refused the key.
    pub fn tls13(p: &dyn Provider, alg: AeadAlg, key: &[u8], iv: &[u8]) -> Result<Self> {
        Ok(Self::Tls13 {
            aead: p.aead(alg, key)?,
            iv: Secret::new(iv.to_vec()),
            tag_len: alg.tag_len(),
        })
    }

    /// TLS 1.2 AEAD protection: `iv` is the key block's IV (4 octets for GCM and CCM, 12 for
    /// ChaCha20-Poly1305); for sending, the explicit nonces count up from `first_explicit`.
    ///
    /// # Errors
    /// The provider refused the key.
    pub fn aead12(
        p: &dyn Provider,
        alg: AeadAlg,
        key: &[u8],
        iv: &[u8],
        first_explicit: u64,
    ) -> Result<Self> {
        Ok(Self::Aead12 {
            aead: p.aead(alg, key)?,
            iv: Secret::new(iv.to_vec()),
            explicit: alg != AeadAlg::ChaCha20Poly1305,
            tag_len: alg.tag_len(),
            next_explicit: first_explicit,
            tag_error_func: match alg {
                AeadAlg::ChaCha20Poly1305 => None,
                AeadAlg::Aes128Ccm
                | AeadAlg::Aes256Ccm
                | AeadAlg::Aes128Ccm8
                | AeadAlg::Aes256Ccm8
                | AeadAlg::Sm4Ccm => Some("ossl_ccm_stream_update"),
                _ => Some("ossl_gcm_stream_update"),
            },
        })
    }

    /// TLS 1.0–1.2 CBC (or NULL) protection for `version`.
    ///
    /// # Errors
    /// The provider refused the key.
    #[allow(clippy::too_many_arguments, reason = "the suite's parameters")]
    pub fn cbc12(
        p: &dyn Provider,
        alg: CipherAlg,
        key: &[u8],
        iv: &[u8],
        mac_hash: HashAlg,
        mac_key: &[u8],
        version: u16,
        etm: bool,
        encrypt: bool,
    ) -> Result<Self> {
        let cipher = if alg == CipherAlg::Null {
            None
        } else {
            Some(p.cipher(alg, key, encrypt)?)
        };
        Ok(Self::Cbc12 {
            cipher,
            block_len: alg.block_len(),
            mac_hash,
            mac_key: Secret::new(mac_key.to_vec()),
            iv: if iv.len() == alg.block_len() {
                iv.to_vec()
            } else {
                vec![0; alg.block_len()]
            },
            // DTLS (counted down, `DTLS1_BAD_VER` 0x0100 included) always sends the IV.
            explicit_iv: version >= tls1_1()
                || version == u16::try_from(abi::DTLS1_BAD_VER).unwrap_or(0x0100),
            etm,
        })
    }

    /// Whether records are protected at all.
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

fn tls1_0() -> u16 {
    u16::try_from(abi::TLS1_VERSION).unwrap_or(0x0301)
}

fn tls1_1() -> u16 {
    u16::try_from(abi::TLS1_1_VERSION).unwrap_or(0x0302)
}

fn tls1_2() -> u16 {
    u16::try_from(abi::TLS1_2_VERSION).unwrap_or(0x0303)
}

/// Which header checks apply, as OpenSSL's record methods make them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Before protection (`tlsany_meth`): any version until one is set (`None`), then that
    /// version; after a HelloRetryRequest, TLS 1.3, whose plaintext record versions are ignored.
    Plain(Option<u16>),
    /// TLS 1.0–1.2 protection (`tls1_meth`): the version must match exactly.
    Tls12(u16),
    /// TLS 1.3 protection (`tls13_meth`).
    Tls13,
}

/// A record read: its header as received, and its (unprotected) content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The content type: TLS 1.3's inner type for a protected record.
    pub content_type: ContentType,
    /// The header's version (`SSL2_VERSION` for an SSLv2-format ClientHello).
    pub version: u16,
    /// The header as received (5 octets; 2 for SSLv2), for the message callback.
    pub header: Vec<u8>,
    /// The plaintext.
    pub data: Vec<u8>,
    /// Whether TLS 1.3 protected it (its inner content type goes to the message callback).
    pub inner: bool,
}

/// What [`RecordReader::read`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Read {
    /// More input is needed: at least this many octets in all.
    NeedMore(usize),
    /// A record, from the first `consumed` octets.
    Record {
        /// The octets of input the record took.
        consumed: usize,
        /// The record.
        record: Record,
    },
    /// A TLS 1.3 record that didn't decrypt while [`RecordReader::skip_undecryptable`] was set
    /// (rejected early data, treated as an empty record): its header and protected length,
    /// from the first `consumed` octets. The sequence number starts again at 0.
    Skipped {
        /// The octets of input the record took.
        consumed: usize,
        /// The header as received.
        header: Vec<u8>,
        /// The record's protected length.
        len: usize,
    },
    /// A TLS 1.3 compatibility ChangeCipherSpec (ignored, but given to the message callback),
    /// from the first `consumed` octets.
    IgnoredCcs {
        /// The octets of input the record took.
        consumed: usize,
        /// The header as received.
        header: Vec<u8>,
    },
}

/// The read side of the record layer.
#[derive(Debug)]
pub struct RecordReader {
    mode: Mode,
    protection: Protection,
    seq: u64,
    /// The largest plaintext the peer may send (`max_fragment_length`, `record_size_limit`).
    pub max_frag_len: usize,
    /// `SSL_CTX_set_default_read_buffer_len`'s length (0: none).
    pub default_read_len: usize,
    empty_records: u32,
    first_record: bool,
    server: bool,
    /// TLS 1.3: whether compatibility ChangeCipherSpec records may still arrive.
    pub first_handshake: bool,
    /// TLS 1.3: whether a plaintext alert may arrive (before the peer's keys are known).
    pub allow_plain_alerts: bool,
    /// Whether a record's header is in and its body isn't yet (`SSL_ST_READ_BODY`).
    reading_body: bool,
    /// Whether a TLS 1.3 record that doesn't decrypt is skipped rather than fatal (a server
    /// skipping early data it rejected: `skip_early_data`).
    pub skip_undecryptable: bool,
    /// DTLS's read state (`None` for TLS).
    pub dtls: Option<dtls::ReadState>,
    /// The sequence number of the DTLS record being unprotected (`epoch || sequence`).
    dtls_seq: Option<u64>,
    /// Whether the last unprotection failed an encrypt-then-MAC check (fatal in DTLS too).
    etm_failed: bool,
}

impl RecordReader {
    /// A reader for a client or server, before any protection.
    #[must_use]
    pub fn new(server: bool) -> Self {
        Self {
            mode: Mode::Plain(None),
            protection: Protection::Null,
            seq: 0,
            max_frag_len: MAX_PLAIN,
            default_read_len: 0,
            empty_records: 0,
            first_record: true,
            server,
            reading_body: false,
            first_handshake: true,
            allow_plain_alerts: false,
            skip_undecryptable: false,
            dtls: None,
            dtls_seq: None,
            etm_failed: false,
        }
    }

    /// A DTLS reader.
    #[must_use]
    pub fn new_dtls(server: bool) -> Self {
        Self {
            dtls: Some(dtls::ReadState::default()),
            ..Self::new(server)
        }
    }

    /// The current checks.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Sets the version plaintext records must carry (after the ServerHello).
    pub fn set_plain_version(&mut self, version: Option<u16>) {
        if let Mode::Plain(_) = self.mode {
            self.mode = Mode::Plain(version);
        }
    }

    /// Starts new protection (a new epoch: the sequence number restarts at 0; DTLS's epoch
    /// counts up, and the next epoch's buffered records are read again).
    pub fn set_protection(&mut self, mode: Mode, protection: Protection) {
        self.mode = mode;
        self.protection = protection;
        self.seq = 0;
        if let Some(d) = self.dtls.as_mut() {
            d.next_epoch();
        }
    }

    /// The next sequence number.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.seq
    }

    /// The size of OpenSSL's read buffer, which caps a record's length.
    fn buffer_len(&self) -> usize {
        let len = self
            .max_frag_len
            .saturating_add(size(abi::SSL3_RT_MAX_ENCRYPTED_OVERHEAD))
            .saturating_add(HEADER_LEN)
            .saturating_add(size(abi::SSL3_ALIGN_PAYLOAD).saturating_sub(1));
        len.max(self.default_read_len)
    }

    /// Whether a record's header was read and its body is still awaited (OpenSSL's read state
    /// `SSL_ST_READ_BODY`, from the header until the whole record is in, and after a header
    /// that failed its checks).
    #[must_use]
    pub fn reading_body(&self) -> bool {
        self.reading_body
    }

    /// Reads the next record from `buf`, the input not yet consumed.
    ///
    /// # Errors
    /// A fatal error, with OpenSSL's alert and reason.
    pub fn read(&mut self, p: &dyn Provider, buf: &[u8]) -> Result<Read> {
        self.read_record(p, buf).in_func("tls_get_more_records")
    }

    /// See [`RecordReader::read`].
    fn read_record(&mut self, p: &dyn Provider, buf: &[u8]) -> Result<Read> {
        let Some(head) = buf.get(..HEADER_LEN) else {
            return Ok(Read::NeedMore(HEADER_LEN));
        };
        self.reading_body = true;
        let b = |i: usize| head.get(i).copied().unwrap_or(0);
        let sslv2len = (usize::from(b(0)) << 8) | usize::from(b(1));
        // The first record a server receives may be an SSLv2-format ClientHello.
        if self.server
            && self.first_record
            && self.mode == Mode::Plain(None)
            && sslv2len & 0x8000 != 0
            && b(2) == octet(abi::SSL2_MT_CLIENT_HELLO)
        {
            let len = sslv2len & 0x7fff;
            if len < MIN_SSL2_RECORD_LEN {
                return Err(fatal(abi::SSL_AD_DECODE_ERROR, abi::SSL_R_LENGTH_TOO_SHORT)
                    .in_func("tls_validate_record_header"));
            }
            if len > self.buffer_len().saturating_sub(SSL2_HEADER_LEN) {
                return Err(fatal(
                    abi::SSL_AD_RECORD_OVERFLOW,
                    abi::SSL_R_PACKET_LENGTH_TOO_LONG,
                ));
            }
            let total = SSL2_HEADER_LEN.saturating_add(len);
            let Some(body) = buf.get(SSL2_HEADER_LEN..total) else {
                return Ok(Read::NeedMore(total));
            };
            self.reading_body = false;
            self.first_record = false;
            return Ok(Read::Record {
                consumed: total,
                record: Record {
                    content_type: handshake(),
                    version: SSL2_VERSION,
                    header: head.get(..SSL2_HEADER_LEN).unwrap_or_default().to_vec(),
                    data: body.to_vec(),
                    inner: false,
                },
            });
        }
        let ty = b(0);
        let version = (u16::from(b(1)) << 8) | u16::from(b(2));
        let len = (usize::from(b(3)) << 8) | usize::from(b(4));
        if version == SSL2_VERSION {
            return Err(fatal(
                abi::SSL_AD_PROTOCOL_VERSION,
                abi::SSL_R_WRONG_VERSION_NUMBER,
            ));
        }
        self.validate_header(ty, version, len, head)
            .in_func(self.method_func(true))?;
        if len > self.buffer_len().saturating_sub(HEADER_LEN) {
            return Err(fatal(
                abi::SSL_AD_RECORD_OVERFLOW,
                abi::SSL_R_PACKET_LENGTH_TOO_LONG,
            ));
        }
        let total = HEADER_LEN.saturating_add(len);
        let Some(body) = buf.get(HEADER_LEN..total) else {
            return Ok(Read::NeedMore(total));
        };
        self.reading_body = false;
        self.first_record = false;
        let header = head.to_vec();

        // TLS 1.3's compatibility ChangeCipherSpec: exactly 0x01, ignored, counted as empty;
        // also in plaintext once a HelloRetryRequest told the client TLS 1.3 is coming
        // (`tlsany_meth` after HRR; shared fix, fork F).
        if ty == change_cipher_spec()
            && (self.mode == Mode::Tls13 || self.mode == Mode::Plain(Some(tls13())))
            && self.first_handshake
        {
            if body != [1] {
                return Err(fatal(
                    abi::SSL_AD_UNEXPECTED_MESSAGE,
                    abi::SSL_R_INVALID_CCS_MESSAGE,
                ));
            }
            self.count_empty(abi::SSL_R_UNEXPECTED_CCS_MESSAGE)?;
            return Ok(Read::IgnoredCcs {
                consumed: total,
                header,
            });
        }

        let mut record = Record {
            content_type: ty,
            version,
            header,
            data: body.to_vec(),
            inner: false,
        };
        let tls13 = matches!(
            self.protection,
            Protection::Tls13 { .. } | Protection::Tls13Integrity { .. }
        );
        if let Err(e) = self.unprotect(p, &mut record) {
            if self.skip_undecryptable && tls13 && ty == application_data() {
                // Valid early data that can't be decrypted fails here: it is skipped like an
                // empty record, and the sequence starts again (`tls_get_more_records`).
                self.seq = 0;
                return Ok(Read::Skipped {
                    consumed: total,
                    header: record.header,
                    len,
                });
            }
            return Err(e);
        }
        self.post_process(&mut record)
            .in_func(self.method_func(false))?;
        if self.max_frag_len != MAX_PLAIN && record.data.len() > self.max_frag_len {
            return Err(fatal(
                abi::SSL_AD_RECORD_OVERFLOW,
                abi::SSL_R_DATA_LENGTH_TOO_LONG,
            ));
        }
        if record.data.is_empty() {
            self.count_empty(abi::SSL_R_RECORD_TOO_SMALL)?;
        } else {
            self.empty_records = 0;
        }
        Ok(Read::Record {
            consumed: total,
            record,
        })
    }

    /// The current method's `validate_record_header` (`header`) or `post_process_record`.
    fn method_func(&self, header: bool) -> &'static str {
        match (self.mode, header) {
            (Mode::Tls13, true) => "tls13_validate_record_header",
            (Mode::Tls13, false) => "tls13_post_process_record",
            (Mode::Tls12(_), true) => "tls_default_validate_record_header",
            (Mode::Plain(_), true) => "tls_validate_record_header",
            (_, false) => "tls_default_post_process_record",
        }
    }

    /// One more empty record; too many in a row is fatal.
    fn count_empty(&mut self, reason: core::ffi::c_int) -> Result<()> {
        self.empty_records = self.empty_records.saturating_add(1);
        if self.empty_records > MAX_EMPTY_RECORDS {
            return Err(fatal(abi::SSL_AD_UNEXPECTED_MESSAGE, reason));
        }
        Ok(())
    }

    /// The header checks of the current method (`validate_record_header`).
    fn validate_header(
        &self,
        ty: ContentType,
        version: u16,
        len: usize,
        head: &[u8],
    ) -> Result<()> {
        match self.mode {
            Mode::Plain(None) => {
                if version >> 8 != 3 {
                    if self.first_record {
                        return Err(quiet(not_tls_reason(head)));
                    }
                    return Err(fatal(
                        abi::SSL_AD_PROTOCOL_VERSION,
                        abi::SSL_R_WRONG_VERSION_NUMBER,
                    ));
                }
            }
            Mode::Plain(Some(v)) if v == tls13() => {}
            Mode::Plain(Some(v)) => {
                if version != v {
                    if v & 0xff00 == version & 0xff00 && ty == alert() {
                        // Probably a fatal alert in the peer's version: end without one.
                        return Err(quiet(abi::SSL_R_WRONG_VERSION_NUMBER));
                    }
                    return Err(fatal(
                        abi::SSL_AD_PROTOCOL_VERSION,
                        abi::SSL_R_WRONG_VERSION_NUMBER,
                    ));
                }
            }
            Mode::Tls12(v) => {
                if version != v {
                    return Err(fatal(
                        abi::SSL_AD_PROTOCOL_VERSION,
                        abi::SSL_R_WRONG_VERSION_NUMBER,
                    ));
                }
                // The compression overhead isn't allowed: no compression is ever negotiated.
                let max = size(abi::SSL3_RT_MAX_ENCRYPTED_LENGTH)
                    .saturating_sub(size(abi::SSL3_RT_MAX_COMPRESSED_OVERHEAD));
                if len > max {
                    return Err(fatal(
                        abi::SSL_AD_RECORD_OVERFLOW,
                        abi::SSL_R_ENCRYPTED_LENGTH_TOO_LONG,
                    ));
                }
                return Ok(());
            }
            Mode::Tls13 => {
                if ty != application_data()
                    && (ty != change_cipher_spec() || !self.first_handshake)
                    && (ty != alert() || !self.allow_plain_alerts)
                {
                    return Err(fatal(
                        abi::SSL_AD_UNEXPECTED_MESSAGE,
                        abi::SSL_R_BAD_RECORD_TYPE,
                    ));
                }
                if version != tls1_2() {
                    return Err(fatal(
                        abi::SSL_AD_DECODE_ERROR,
                        abi::SSL_R_WRONG_VERSION_NUMBER,
                    ));
                }
                if len > size(abi::SSL3_RT_MAX_TLS13_ENCRYPTED_LENGTH) {
                    return Err(fatal(
                        abi::SSL_AD_RECORD_OVERFLOW,
                        abi::SSL_R_ENCRYPTED_LENGTH_TOO_LONG,
                    ));
                }
                return Ok(());
            }
        }
        // The plaintext methods (`tlsany_meth`).
        if len > MAX_PLAIN {
            return Err(fatal(
                abi::SSL_AD_RECORD_OVERFLOW,
                abi::SSL_R_DATA_LENGTH_TOO_LONG,
            ));
        }
        Ok(())
    }

    /// Removes the protection of `record` in place.
    fn unprotect(&mut self, p: &dyn Provider, record: &mut Record) -> Result<()> {
        let fixed = self.dtls_seq;
        match &mut self.protection {
            Protection::Null => Ok(()),
            Protection::Tls13 { aead, iv, tag_len } => {
                // A plaintext alert where one is allowed passes as it is.
                if record.content_type == alert() {
                    return Ok(());
                }
                if record.data.len() < tag_len.saturating_add(1) {
                    return Err(bad_mac());
                }
                let seq = take_seq(fixed, &mut self.seq)?;
                let nonce = xor_nonce(iv.bytes(), seq);
                aead.open(&nonce, &record.header, &mut record.data)
                    .map_err(|_| bad_mac())?;
                record.inner = true;
                Ok(())
            }
            Protection::Tls13Integrity { hash, key, iv } => {
                if record.content_type == alert() {
                    return Ok(());
                }
                let tag_len = hash.len();
                let Some(n) = record.data.len().checked_sub(tag_len).filter(|&n| n >= 1) else {
                    return Err(bad_mac());
                };
                let seq = take_seq(fixed, &mut self.seq)?;
                let nonce = xor_nonce(iv.bytes(), seq);
                let tag = record.data.split_off(n);
                let want = crate::keysched::hmac(
                    p,
                    *hash,
                    key.bytes(),
                    &[&nonce, &record.header, &record.data],
                )?;
                if !bool::from(want.ct_eq(&tag)) {
                    return Err(bad_mac());
                }
                record.inner = true;
                Ok(())
            }
            Protection::Aead12 {
                aead,
                iv,
                explicit,
                tag_len,
                tag_error_func,
                ..
            } => {
                let eiv: usize = if *explicit { 8 } else { 0 };
                if record.data.len() < eiv.saturating_add(*tag_len) {
                    return Err(bad_mac());
                }
                let seq = take_seq(fixed, &mut self.seq)?;
                let nonce = if *explicit {
                    [iv.bytes(), record.data.get(..8).unwrap_or_default()].concat()
                } else {
                    xor_nonce(iv.bytes(), seq)
                };
                let mut ct = record.data.split_off(eiv);
                let plain_len = ct.len().saturating_sub(*tag_len);
                let aad = mac_header(seq, record.content_type, record.version, plain_len)?;
                aead.open(&nonce, &aad, &mut ct)
                    .map_err(|_| match tag_error_func {
                        Some(func) => bad_mac().caused_by(Cause {
                            lib: abi::ERR_LIB_PROV,
                            reason: abi::PROV_R_CIPHER_OPERATION_FAILED,
                            func,
                        }),
                        None => bad_mac(),
                    })?;
                record.data = ct;
                Ok(())
            }
            Protection::Cbc12 {
                cipher,
                block_len,
                mac_hash,
                mac_key,
                iv,
                explicit_iv,
                etm,
            } => {
                let mac_len = mac_hash.len();
                let seq = fixed.unwrap_or(self.seq);
                if *etm {
                    // Encrypt-then-MAC: the MAC covers the ciphertext, all public.
                    let Some(n) = record.data.len().checked_sub(mac_len) else {
                        self.etm_failed = true;
                        return Err(fatal(abi::SSL_AD_DECODE_ERROR, abi::SSL_R_LENGTH_TOO_SHORT));
                    };
                    let tag = record.data.split_off(n);
                    let header = mac_header(seq, record.content_type, record.version, n)?;
                    let want = crate::keysched::hmac(
                        p,
                        *mac_hash,
                        mac_key.bytes(),
                        &[&header, &record.data],
                    )?;
                    if !bool::from(want.ct_eq(&tag)) {
                        self.etm_failed = true;
                        return Err(bad_mac());
                    }
                }
                let bs = *block_len;
                let Some(c) = cipher else {
                    // The NULL cipher: only a MAC.
                    take_seq(fixed, &mut self.seq)?;
                    if *etm {
                        return Ok(());
                    }
                    let Some(n) = record.data.len().checked_sub(mac_len) else {
                        return Err(bad_mac());
                    };
                    let tag = record.data.split_off(n);
                    let header = mac_header(seq, record.content_type, record.version, n)?;
                    let want = crate::keysched::hmac(
                        p,
                        *mac_hash,
                        mac_key.bytes(),
                        &[&header, &record.data],
                    )?;
                    if !bool::from(want.ct_eq(&tag))
                        || record.data.len()
                            > size(abi::SSL3_RT_MAX_COMPRESSED_LENGTH).saturating_add(mac_len)
                    {
                        return Err(bad_mac());
                    }
                    return Ok(());
                };
                // Publicly invalid: no whole blocks.
                if record.data.is_empty() || !record.data.len().is_multiple_of(bs) {
                    return Err(bad_mac());
                }
                take_seq(fixed, &mut self.seq)?;
                if *explicit_iv && record.data.len() < bs {
                    return Err(bad_mac());
                }
                let last = record
                    .data
                    .get(record.data.len().saturating_sub(bs)..)
                    .unwrap_or_default()
                    .to_vec();
                let chain_iv = core::mem::replace(iv, last);
                let mut ct = core::mem::take(&mut record.data);
                c.crypt(&chain_iv, &mut ct)?;
                if *explicit_iv {
                    // The explicit IV's block decrypts to nothing of use; what follows it
                    // decrypts the same whatever came before.
                    ct.drain(..bs);
                }
                if *etm {
                    // The padding is public now: the MAC already passed.
                    let pad = usize::from(ct.last().copied().unwrap_or(0));
                    let n = ct
                        .len()
                        .checked_sub(pad.saturating_add(1))
                        .ok_or_else(bad_mac)?;
                    if !ct.iter().skip(n).all(|&b| usize::from(b) == pad) {
                        return Err(bad_mac());
                    }
                    ct.truncate(n);
                    record.data = ct;
                    return Ok(());
                }
                // MAC-then-encrypt, in constant time (and in the core's data-independent timing
                // mode: `rustyssl_crypto::dit`).
                let (data_len, mac_ok) = rustyssl_crypto::dit::with(|| {
                    let (data_len, mac, good) = cbc_remove_padding_and_mac(p, &ct, bs, mac_len)?;
                    let header = mac_header(seq, record.content_type, record.version, data_len)?;
                    let want = p.tls_cbc_mac(*mac_hash, mac_key.bytes(), &header, &ct, data_len)?;
                    Ok::<_, Error>((data_len, want.ct_eq(&mac) & good))
                })?;
                if !bool::from(mac_ok)
                    || data_len > size(abi::SSL3_RT_MAX_COMPRESSED_LENGTH).saturating_add(mac_len)
                {
                    return Err(bad_mac());
                }
                ct.truncate(data_len);
                record.data = ct;
                Ok(())
            }
        }
    }

    /// The checks after unprotection (`post_process_record`).
    fn post_process(&self, record: &mut Record) -> Result<()> {
        if self.mode == Mode::Tls13 {
            if record.content_type != alert() {
                if record.data.is_empty() || record.content_type != application_data() {
                    return Err(fatal(
                        abi::SSL_AD_UNEXPECTED_MESSAGE,
                        abi::SSL_R_BAD_RECORD_TYPE,
                    ));
                }
                // Strip the zero padding; the last nonzero octet is the type (OpenSSL stops at the
                // first octet, so an all-zero plaintext has type 0).
                let mut end = record.data.len().saturating_sub(1);
                while end > 0 && record.data.get(end) == Some(&0) {
                    end = end.saturating_sub(1);
                }
                record.content_type = record.data.get(end).copied().unwrap_or(0);
                record.data.truncate(end);
            }
            if record.data.len() > MAX_PLAIN {
                return Err(fatal(
                    abi::SSL_AD_RECORD_OVERFLOW,
                    abi::SSL_R_DATA_LENGTH_TOO_LONG,
                ));
            }
            let t = record.content_type;
            let common = "tls13_common_post_process_record";
            if t != application_data() && t != alert() && t != handshake() {
                return Err(
                    fatal(abi::SSL_AD_UNEXPECTED_MESSAGE, abi::SSL_R_BAD_RECORD_TYPE)
                        .in_func(common),
                );
            }
            if (t == handshake() || t == alert()) && record.data.is_empty() {
                return Err(
                    fatal(abi::SSL_AD_UNEXPECTED_MESSAGE, abi::SSL_R_BAD_LENGTH).in_func(common)
                );
            }
            return Ok(());
        }
        if record.data.len() > MAX_PLAIN {
            return Err(fatal(
                abi::SSL_AD_RECORD_OVERFLOW,
                abi::SSL_R_DATA_LENGTH_TOO_LONG,
            ));
        }
        Ok(())
    }
}

/// `TLS1_3_VERSION`.
fn tls13() -> u16 {
    u16::try_from(abi::TLS1_3_VERSION).unwrap_or(0x0304)
}

/// Why a first record that isn't TLS fails: an HTTP request, a proxy request, or anything else.
fn not_tls_reason(head: &[u8]) -> core::ffi::c_int {
    const HTTP: [&[u8]; 8] = [
        b"GET ", b"POST ", b"HEAD ", b"PATCH", b"OPTIO", b"DELET", b"TRACE", b"PUT ",
    ];
    if HTTP.iter().any(|m| head.starts_with(m)) {
        abi::SSL_R_HTTP_REQUEST
    } else if head.starts_with(b"CONNE") {
        abi::SSL_R_HTTPS_PROXY_REQUEST
    } else {
        abi::SSL_R_WRONG_VERSION_NUMBER
    }
}

/// The low octet of a mask.
fn low_octet(mask: usize) -> u8 {
    let [b, ..] = mask.to_le_bytes();
    b
}

/// A mask the optimizer can't see through: without it LLVM recognizes the masks below as
/// comparisons and may branch on them or shorten a loop at a secret bound (measured: the
/// Lucky13 dudect target, `tests/timing/dudect.c` `tls-cbc-record`).
fn barrier(mask: usize) -> usize {
    core::hint::black_box(mask)
}

/// An all-ones mask when `a >= b` (`constant_time_ge_s`), without branching on secrets.
fn ct_ge(a: usize, b: usize) -> usize {
    // The borrow out of a - b, in the top bit of (a ^ ((a ^ b) | ((a - b) ^ b))).
    let lt = (a ^ ((a ^ b) | (a.wrapping_sub(b) ^ b))) >> (usize::BITS - 1);
    barrier(lt.wrapping_sub(1))
}

/// An all-ones mask when `a == b`.
fn ct_eq_s(a: usize, b: usize) -> usize {
    let x = a ^ b;
    // x - 1 has its top bit set (with x's clear) only for x == 0.
    let z = (!x & x.wrapping_sub(1)) >> (usize::BITS - 1);
    barrier(0usize.wrapping_sub(z))
}

/// An all-ones mask when `a < b`.
fn ct_lt(a: usize, b: usize) -> usize {
    !ct_ge(a, b)
}

/// `tls1_cbc_remove_padding_and_mac` and `ssl3_cbc_copy_mac` together, for a decrypted
/// MAC-then-encrypt record `rec` of public length `rec.len()`: the data's length (secret), the
/// MAC as received (a random one if the padding is bad), and whether the padding was good, all
/// computed in constant time. A record too short for the padding octet and the MAC is publicly
/// invalid.
fn cbc_remove_padding_and_mac(
    p: &dyn Provider,
    rec: &[u8],
    block_len: usize,
    mac_len: usize,
) -> Result<(usize, Vec<u8>, subtle::Choice)> {
    let reclen = rec.len();
    let overhead = mac_len.saturating_add(1);
    if overhead > reclen {
        return Err(bad_mac());
    }
    let padding_length = barrier(usize::from(rec.last().copied().unwrap_or(0)));
    let mut good = ct_ge(reclen, overhead.wrapping_add(padding_length));
    // Check the most padding there can be, so the work doesn't depend on its length.
    let to_check = MAX_PADDING.min(reclen);
    for i in 0..to_check {
        let mask = ct_ge(padding_length, i) & 0xff;
        let b = usize::from(
            rec.get(reclen.wrapping_sub(1).wrapping_sub(i))
                .copied()
                .unwrap_or(0),
        );
        good = barrier(good & !(mask & (padding_length ^ b)));
    }
    good = ct_eq_s(0xff, good & 0xff);
    let len = barrier(reclen.wrapping_sub(good & padding_length.wrapping_add(1)));
    // The block length only bounds the padding, which the 256-octet scan covers.
    let _ = block_len;

    // The MAC ends where the padding starts; copy it out without the position leaking.
    let mac_end = len;
    let mac_start = mac_end.wrapping_sub(mac_len);
    let data_len = mac_start;
    let mut rand_mac = vec![0u8; mac_len];
    p.random(&mut rand_mac, false)?;
    let scan_start = reclen.saturating_sub(mac_len.saturating_add(MAX_PADDING));
    let mut rotated = vec![0u8; mac_len];
    let mut in_mac = 0usize;
    let mut rotate_offset = 0usize;
    let mut j = 0usize;
    for i in scan_start..reclen {
        let started = ct_eq_s(i, mac_start);
        let ended = ct_lt(i, mac_end);
        let b = rec.get(i).copied().unwrap_or(0);
        in_mac |= started;
        in_mac &= ended;
        rotate_offset |= j & started;
        if let Some(r) = rotated.get_mut(j) {
            *r |= b & low_octet(in_mac);
        }
        j = j.wrapping_add(1);
        j &= ct_lt(j, mac_len);
    }
    // Rotate it into place, reading every octet each time.
    let mut out = vec![0u8; mac_len];
    for (i, o) in out.iter_mut().enumerate() {
        let mut v = 0u8;
        for (k, &r) in rotated.iter().enumerate() {
            v |= r & low_octet(ct_eq_s(k, rotate_offset));
        }
        rotate_offset = rotate_offset.wrapping_add(1);
        rotate_offset &= ct_lt(rotate_offset, mac_len);
        let g = low_octet(good);
        *o = (v & g) | (rand_mac.get(i).copied().unwrap_or(0) & !g);
    }
    Ok((data_len, out, subtle::Choice::from(u8::from(good & 1 == 1))))
}

/// How a writer pads TLS 1.3 records.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Padding {
    /// No padding.
    #[default]
    None,
    /// `SSL_CTX_set_block_padding_ex`: application data to a multiple of the first, handshake
    /// and alert records to a multiple of the second (0: none).
    Block(usize, usize),
    /// Exactly this many octets on each record (the record-padding callback's answer, which the
    /// caller asks for before writing, outside the core).
    Exact(usize),
}

/// The application's record padding callback, as capi wraps it.
#[derive(Clone)]
pub struct PaddingHook {
    /// A TLS 1.3 record's content type and length (with the type octet) to the padding to
    /// add; `None` when there is no callback now.
    pub pad: std::sync::Arc<dyn Fn(ContentType, usize) -> Option<usize> + Send + Sync>,
    /// Whether there is a callback now: asked when a write epoch starts, which pads with the
    /// callback for its lifetime if so (OpenSSL's record layer takes the padding function
    /// when it is made).
    pub present: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
}

impl core::fmt::Debug for PaddingHook {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PaddingHook")
    }
}

/// The write side of the record layer.
#[derive(Debug)]
pub struct RecordWriter {
    mode: Mode,
    protection: Protection,
    seq: u64,
    /// The version written in plaintext records' headers (and TLS 1.0–1.2's protected ones).
    pub version: u16,
    /// The largest fragment to send (`max_send_fragment`, the peer's `max_fragment_length`
    /// or `record_size_limit`).
    pub max_frag_len: usize,
    /// TLS 1.3's padding.
    pub padding: Padding,
    /// The record padding callback, which takes the place of `padding` in an epoch that
    /// started with it set (`tls13_add_record_padding`).
    pub pad_hook: Option<PaddingHook>,
    /// Whether this epoch pads with the callback.
    pad_with_hook: bool,
    /// TLS 1.0 CBC's empty-fragment countermeasure (off with `SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS`).
    pub empty_fragments: bool,
    /// TLS 1.3: send alerts in the clear (before the keys are known).
    pub plain_alerts: bool,
    /// DTLS's write state (`None` for TLS).
    pub dtls: Option<dtls::WriteState>,
}

impl RecordWriter {
    /// A writer before any protection, writing `version` in the headers.
    #[must_use]
    pub fn new(version: u16) -> Self {
        Self {
            mode: Mode::Plain(None),
            protection: Protection::Null,
            seq: 0,
            version,
            max_frag_len: MAX_PLAIN,
            padding: Padding::None,
            pad_hook: None,
            pad_with_hook: false,
            empty_fragments: false,
            plain_alerts: false,
            dtls: None,
        }
    }

    /// A DTLS writer.
    #[must_use]
    pub fn new_dtls(version: u16) -> Self {
        Self {
            dtls: Some(dtls::WriteState::default()),
            ..Self::new(version)
        }
    }

    /// Starts new protection (a new epoch). DTLS keeps the previous epoch's state for
    /// retransmitting the flight that changed it.
    pub fn set_protection(&mut self, mode: Mode, protection: Protection) {
        if let Some(d) = self.dtls.as_mut() {
            let old_mode = core::mem::replace(&mut self.mode, mode);
            let old = core::mem::replace(&mut self.protection, protection);
            d.next_epoch(old_mode, old);
            self.pad_with_hook = false;
            return;
        }
        self.mode = mode;
        self.protection = protection;
        self.seq = 0;
        self.pad_with_hook = self.pad_hook.as_ref().is_some_and(|h| (h.present)());
    }

    /// The current protection's mode.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The next sequence number.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.seq
    }

    /// Writes `data` of content type `ty` as records, fragmented to `max_frag_len`, appending
    /// them to `out`. An empty `data` writes one empty record.
    ///
    /// # Errors
    /// The provider failed, or the sequence number wrapped.
    pub fn write(
        &mut self,
        p: &dyn Provider,
        ty: ContentType,
        data: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<()> {
        let tls10_cbc = matches!(
            self.protection,
            Protection::Cbc12 {
                cipher: Some(_),
                explicit_iv: false,
                ..
            }
        );
        if self.empty_fragments && tls10_cbc && ty == application_data() && !data.is_empty() {
            self.write_one(p, ty, &[], out)?;
        }
        let max = self.max_frag_len.clamp(1, MAX_PLAIN);
        if data.is_empty() {
            return self.write_one(p, ty, &[], out);
        }
        for chunk in data.chunks(max) {
            self.write_one(p, ty, chunk, out)?;
        }
        Ok(())
    }

    /// One record.
    fn write_one(
        &mut self,
        p: &dyn Provider,
        ty: ContentType,
        data: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<()> {
        // DTLS: every record, protected or not, takes the next sequence number of its epoch.
        let fixed = match self.dtls.as_mut() {
            Some(d) => Some(d.take_seq()?),
            None => None,
        };
        let (outer_ty, version, body) = match &mut self.protection {
            Protection::Null => (ty, self.version, data.to_vec()),
            Protection::Tls13 { aead, iv, tag_len } => {
                if self.plain_alerts && ty == alert() {
                    (ty, tls1_2(), data.to_vec())
                } else {
                    let mut inner = data.to_vec();
                    inner.push(ty);
                    let hook = self.pad_hook.as_ref().filter(|_| self.pad_with_hook);
                    let pad = padding_for(hook, self.padding, ty, inner.len(), self.max_frag_len);
                    pad13(&mut inner, ty, pad, self.max_frag_len);
                    let seq = take_seq(fixed, &mut self.seq)?;
                    let nonce = xor_nonce(iv.bytes(), seq);
                    let len = inner.len().saturating_add(*tag_len);
                    let header = header_bytes(application_data(), tls1_2(), len)?;
                    aead.seal(&nonce, &header, &mut inner)?;
                    (application_data(), tls1_2(), inner)
                }
            }
            Protection::Tls13Integrity { hash, key, iv } => {
                let mut inner = data.to_vec();
                inner.push(ty);
                let hook = self.pad_hook.as_ref().filter(|_| self.pad_with_hook);
                let pad = padding_for(hook, self.padding, ty, inner.len(), self.max_frag_len);
                pad13(&mut inner, ty, pad, self.max_frag_len);
                let seq = take_seq(fixed, &mut self.seq)?;
                let nonce = xor_nonce(iv.bytes(), seq);
                let header = header_bytes(
                    application_data(),
                    tls1_2(),
                    inner.len().saturating_add(hash.len()),
                )?;
                let tag = crate::keysched::hmac(p, *hash, key.bytes(), &[&nonce, &header, &inner])?;
                inner.extend_from_slice(&tag);
                (application_data(), tls1_2(), inner)
            }
            Protection::Aead12 {
                aead,
                iv,
                explicit,
                next_explicit,
                ..
            } => {
                let seq = take_seq(fixed, &mut self.seq)?;
                let (nonce, prefix) = if *explicit {
                    let e = next_explicit.to_be_bytes();
                    *next_explicit = next_explicit.wrapping_add(1);
                    ([iv.bytes(), &e].concat(), e.to_vec())
                } else {
                    (xor_nonce(iv.bytes(), seq), Vec::new())
                };
                let aad = mac_header(seq, ty, self.version, data.len())?;
                let mut ct = data.to_vec();
                aead.seal(&nonce, &aad, &mut ct)?;
                (ty, self.version, [prefix, ct].concat())
            }
            Protection::Cbc12 {
                cipher,
                block_len,
                mac_hash,
                mac_key,
                iv,
                explicit_iv,
                etm,
            } => {
                let seq = take_seq(fixed, &mut self.seq)?;
                let mac = |data: &[u8]| -> Result<Vec<u8>> {
                    let header = mac_header(seq, ty, self.version, data.len())?;
                    crate::keysched::hmac(p, *mac_hash, mac_key.bytes(), &[&header, data])
                };
                match cipher {
                    None => {
                        let tag = mac(data)?;
                        (ty, self.version, [data, &tag].concat())
                    }
                    Some(c) => {
                        let body = cbc_seal(
                            p,
                            c.as_mut(),
                            *block_len,
                            data,
                            &mac,
                            iv,
                            *explicit_iv,
                            *etm,
                        )?;
                        (ty, self.version, body)
                    }
                }
            }
        };
        match fixed {
            Some(seq) => out.extend_from_slice(&dtls::header(outer_ty, version, seq, body.len())?),
            None => out.extend_from_slice(&header_bytes(outer_ty, version, body.len())?),
        }
        out.extend_from_slice(&body);
        Ok(())
    }

    /// DTLS: writes one record of `data` (which must fit one) in `epoch`: the current one, or
    /// the previous one while retransmitting the flight that changed it. Returns `false` (and
    /// writes nothing) when that epoch's state is gone.
    ///
    /// # Errors
    /// The provider failed, or the sequence number wrapped.
    pub fn write_dtls(
        &mut self,
        p: &dyn Provider,
        ty: ContentType,
        data: &[u8],
        epoch: u16,
        out: &mut Vec<u8>,
    ) -> Result<bool> {
        let Some(d) = self.dtls.as_mut() else {
            return Err(Error::internal());
        };
        if d.epoch == epoch {
            self.write_one(p, ty, data, out)?;
            return Ok(true);
        }
        let Some(mut prev) = d.take_prev(epoch) else {
            return Ok(false);
        };
        core::mem::swap(&mut self.mode, &mut prev.mode);
        core::mem::swap(&mut self.protection, &mut prev.protection);
        if let Some(d) = self.dtls.as_mut() {
            d.swap_counters(&mut prev);
        }
        let r = self.write_one(p, ty, data, out);
        core::mem::swap(&mut self.mode, &mut prev.mode);
        core::mem::swap(&mut self.protection, &mut prev.protection);
        if let Some(d) = self.dtls.as_mut() {
            d.swap_counters(&mut prev);
            d.put_prev(prev);
        }
        r.map(|()| true)
    }

    /// DTLS: the current write epoch.
    #[must_use]
    pub fn epoch(&self) -> u16 {
        self.dtls.as_ref().map_or(0, |d| d.epoch)
    }

    /// The largest record overhead of the current protection (`dtls_get_max_record_overhead`:
    /// header, explicit IV, CBC padding, and the MAC or tag).
    #[must_use]
    pub fn max_overhead(&self) -> usize {
        let header = if self.dtls.is_some() {
            dtls::HEADER_LEN
        } else {
            HEADER_LEN
        };
        let extra = match &self.protection {
            Protection::Null => 0,
            Protection::Tls13 { tag_len, .. } => tag_len.saturating_add(1),
            Protection::Tls13Integrity { hash, .. } => hash.len().saturating_add(1),
            Protection::Aead12 {
                explicit, tag_len, ..
            } => tag_len.saturating_add(if *explicit { 8 } else { 0 }),
            Protection::Cbc12 {
                cipher,
                block_len,
                mac_hash,
                explicit_iv,
                ..
            } => {
                let bs = if cipher.is_some() { *block_len } else { 0 };
                let eiv = if *explicit_iv { bs } else { 0 };
                eiv.saturating_add(bs).saturating_add(mac_hash.len())
            }
        };
        header.saturating_add(extra)
    }
}

/// A CBC record's body: the explicit IV (TLS 1.1 and later), the encrypted data, MAC (unless
/// encrypt-then-MAC), and padding, and for encrypt-then-MAC the MAC over all that.
#[allow(clippy::too_many_arguments, reason = "the record's protection state")]
fn cbc_seal(
    p: &dyn Provider,
    c: &mut dyn Cipher,
    block_len: usize,
    data: &[u8],
    mac: &dyn Fn(&[u8]) -> Result<Vec<u8>>,
    iv: &mut Vec<u8>,
    explicit_iv: bool,
    etm: bool,
) -> Result<Vec<u8>> {
    {
        {
            let bs = block_len;
            let mut plain = data.to_vec();
            if !etm {
                let tag = mac(data)?;
                plain.extend_from_slice(&tag);
            }
            let pad = bs.saturating_sub(plain.len().checked_rem(bs).unwrap_or(0));
            let pad_octet = u8::try_from(pad.saturating_sub(1)).map_err(|_| Error::internal())?;
            plain.extend(core::iter::repeat_n(pad_octet, pad));
            if explicit_iv {
                // A random block first, through the chain: its ciphertext is the record's IV.
                let mut e = vec![0u8; bs];
                p.random(&mut e, false)?;
                plain.splice(..0, e);
            }
            c.crypt(iv, &mut plain)?;
            *iv = plain
                .get(plain.len().saturating_sub(bs)..)
                .unwrap_or_default()
                .to_vec();
            let mut body = plain;
            if etm {
                let tag = mac(&body)?;
                body.extend_from_slice(&tag);
            }
            Ok(body)
        }
    }
}

/// A record's padding: the callback's answer (asked only while the record has room for
/// padding, as OpenSSL asks), else the configured padding.
fn padding_for(
    hook: Option<&PaddingHook>,
    padding: Padding,
    ty: ContentType,
    rlen: usize,
    max_frag_len: usize,
) -> Padding {
    if rlen >= max_frag_len {
        return padding;
    }
    match hook.map(|h| (h.pad)(ty, rlen)) {
        // An epoch made with the callback calls it (none now: no padding).
        Some(n) => Padding::Exact(n.unwrap_or(0)),
        None => padding,
    }
}

/// TLS 1.3 padding of an inner plaintext (content and type) as OpenSSL pads it: to the next
/// multiple of the block for the record's kind, never past the fragment limit.
fn pad13(inner: &mut Vec<u8>, ty: ContentType, padding: Padding, max_frag_len: usize) {
    let rlen = inner.len();
    if rlen >= max_frag_len {
        return;
    }
    let (app, hs) = match padding {
        Padding::None => return,
        Padding::Exact(n) => {
            inner.resize(
                rlen.saturating_add(n.min(max_frag_len.saturating_sub(rlen))),
                0,
            );
            return;
        }
        Padding::Block(app, hs) => (app, hs),
    };
    let bp = if ty == application_data() {
        app
    } else if ty == handshake() || ty == alert() {
        hs
    } else {
        0
    };
    if bp == 0 {
        return;
    }
    let rem = rlen.checked_rem(bp).unwrap_or(0);
    if rem == 0 {
        return;
    }
    let pad = bp
        .saturating_sub(rem)
        .min(max_frag_len.saturating_sub(rlen));
    inner.resize(rlen.saturating_add(pad), 0);
}

/// A record header.
fn header_bytes(ty: ContentType, version: u16, len: usize) -> Result<[u8; 5]> {
    let l = u16::try_from(len).map_err(|_| Error::internal())?;
    let [v0, v1] = version.to_be_bytes();
    let [l0, l1] = l.to_be_bytes();
    Ok([ty, v0, v1, l0, l1])
}

/// TLS 1.0's version, for callers that need it.
#[must_use]
pub fn tls10_version() -> u16 {
    tls1_0()
}

pub mod dtls;

#[cfg(test)]
mod tests;
