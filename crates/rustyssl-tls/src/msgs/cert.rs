//! The certificate messages: Certificate (TLS 1.2's list and TLS 1.3's entries, with X.509
//! certificates or a raw public key), CertificateRequest, CertificateVerify, CertificateStatus,
//! and CompressedCertificate.
//!
//! OpenSSL decodes each certificate before reading the next entry (and before the entry's
//! extensions), so [`CertificateReader`] hands them out one at a time: the state machine decodes
//! the DER (with OpenSSL's errors for a bad one) and then asks for the entry's extensions.

use crate::codec::Reader;
use crate::error::{Error, Result};
use crate::msgs::ext::{self, Extension};
use crate::msgs::{OrAlert, ad, encode_with, r};

/// One certificate of a Certificate message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateEntry {
    /// The certificate's DER.
    pub data: Vec<u8>,
    /// TLS 1.3: the entry's extension block's contents; `None` in TLS 1.2.
    pub extensions: Option<Vec<u8>>,
}

/// A Certificate message with X.509 certificates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// TLS 1.3's certificate_request_context; `None` in TLS 1.2.
    pub context: Option<Vec<u8>>,
    /// The certificates, leaf first.
    pub entries: Vec<CertificateEntry>,
}

/// Reads a Certificate message's entries one at a time, as OpenSSL does.
#[derive(Clone, Debug)]
pub struct CertificateReader<'a> {
    list: Reader<'a>,
    tls13: bool,
    from_server: bool,
    context: Option<&'a [u8]>,
}

impl<'a> CertificateReader<'a> {
    /// Starts reading a Certificate's body.
    ///
    /// From the server (`tls_process_server_certificate`): in TLS 1.3 the context must be
    /// empty, and the list must be non-empty and fill the body; each fault is
    /// `SSL_R_LENGTH_MISMATCH` with decode-error.
    ///
    /// From the client (`tls_process_client_certificate`): in TLS 1.3 a broken context vector
    /// is `SSL_R_INVALID_CONTEXT` (the caller compares the context with the one it sent, with
    /// the same error); the list may be empty, and must fill the body
    /// (`SSL_R_LENGTH_MISMATCH`); all decode-error.
    ///
    /// # Errors
    /// As above.
    pub fn new(b: &'a [u8], tls13: bool, from_server: bool) -> Result<Self> {
        let mm = Error::decode(r::LENGTH_MISMATCH);
        let mut rd = Reader::new(b);
        if from_server {
            if tls13 && rd.u8().or_alert(mm)? != 0 {
                return Err(mm);
            }
            let len = rd.u24().or_alert(mm)?;
            let n = usize::try_from(len).map_err(|_| mm)?;
            if rd.len() != n || n == 0 {
                return Err(mm);
            }
            Ok(Self {
                list: rd,
                tls13,
                from_server,
                context: tls13.then_some(&[][..]),
            })
        } else {
            let context = if tls13 {
                Some(
                    rd.vec8()
                        .or_alert(Error::decode(r::INVALID_CONTEXT))?
                        .rest(),
                )
            } else {
                None
            };
            let list = rd.vec24().or_alert(mm)?;
            rd.end().or_alert(mm)?;
            Ok(Self {
                list,
                tls13,
                from_server,
                context,
            })
        }
    }

    /// TLS 1.3's certificate_request_context (empty from a server); `None` in TLS 1.2.
    #[must_use]
    pub fn context(&self) -> Option<&'a [u8]> {
        self.context
    }

    /// Whether every entry has been read.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// The next certificate's DER, or `None` at the end: a truncated entry is
    /// `SSL_R_CERT_LENGTH_MISMATCH` with decode-error. The caller decodes it next (a failure is
    /// `ERR_R_ASN1_LIB`, with bad-certificate from a server and decode-error from a client; DER
    /// that doesn't fill the entry `SSL_R_CERT_LENGTH_MISMATCH`), then, in TLS 1.3, reads the
    /// entry's extensions with [`CertificateReader::extensions`].
    ///
    /// # Errors
    /// As above.
    pub fn next_certificate(&mut self) -> Option<Result<&'a [u8]>> {
        if self.list.is_empty() {
            return None;
        }
        let e = Error::decode(r::CERT_LENGTH_MISMATCH);
        let one = (|| {
            let len = self.list.u24().or_alert(e)?;
            let n = usize::try_from(len).map_err(|_| e)?;
            self.list.take(n).or_alert(e)
        })();
        Some(one)
    }

    /// The current entry's extension block's contents (TLS 1.3; `SSL_R_BAD_LENGTH` with
    /// decode-error when it's broken).
    ///
    /// # Errors
    /// As above.
    pub fn extensions(&mut self) -> Result<&'a [u8]> {
        Ok(self
            .list
            .vec16()
            .or_alert(Error::decode(r::BAD_LENGTH))?
            .rest())
    }

    /// Whether the messages's entries carry extensions (TLS 1.3).
    #[must_use]
    pub fn tls13(&self) -> bool {
        self.tls13
    }

    /// Whether the message came from the server.
    #[must_use]
    pub fn from_server(&self) -> bool {
        self.from_server
    }
}

impl Certificate {
    /// Decodes the whole message with [`CertificateReader`] (the DER isn't checked).
    ///
    /// # Errors
    /// As for the reader.
    pub fn parse(b: &[u8], tls13: bool, from_server: bool) -> Result<Self> {
        let mut rd = CertificateReader::new(b, tls13, from_server)?;
        let context = rd.context().map(<[u8]>::to_vec);
        let mut entries = Vec::new();
        while let Some(c) = rd.next_certificate() {
            let data = c?.to_vec();
            let extensions = if tls13 {
                Some(rd.extensions()?.to_vec())
            } else {
                None
            };
            entries.push(CertificateEntry { data, extensions });
        }
        Ok(Self { context, entries })
    }

    /// The body.
    ///
    /// # Errors
    /// A vector is too long.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_with(|w| {
            if let Some(c) = &self.context {
                w.vec(1, c)?;
            }
            let o = w.open(3);
            for e in &self.entries {
                w.vec(3, &e.data)?;
                if let Some(x) = &e.extensions {
                    w.vec(2, x)?;
                } else if self.context.is_some() {
                    w.u16(0);
                }
            }
            w.close(o)
        })
    }
}

/// A Certificate message carrying a raw public key (RFC 7250).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawPublicKey {
    /// TLS 1.3's certificate_request_context; `None` in TLS 1.2.
    pub context: Option<Vec<u8>>,
    /// The SubjectPublicKeyInfo's DER, or `None` for an empty list (no key sent).
    pub spki: Option<Vec<u8>>,
    /// TLS 1.3: the entry's extension block's contents.
    pub extensions: Option<Vec<u8>>,
}

/// Reads a raw-public-key Certificate in OpenSSL's steps (`tls_process_rpk`).
#[derive(Clone, Debug)]
pub struct RpkReader<'a> {
    /// TLS 1.3's context (the caller compares it, failing with `SSL_R_INVALID_CONTEXT` and
    /// decode-error); `None` in TLS 1.2.
    pub context: Option<&'a [u8]>,
    /// The key's DER, or `None` when the list is empty. The caller decodes it next (a failure
    /// or DER that doesn't fill its vector is `SSL_R_LENGTH_MISMATCH` with decode-error).
    pub spki: Option<&'a [u8]>,
    rest: Reader<'a>,
    expected_rest: usize,
}

impl<'a> RpkReader<'a> {
    /// The context and the key: a broken TLS 1.3 context vector is `SSL_R_INVALID_CONTEXT`; a
    /// list length that doesn't fill the body, a missing key length, or a truncated key
    /// `SSL_R_LENGTH_MISMATCH`; an empty key `SSL_R_EMPTY_RAW_PUBLIC_KEY`; all decode-error.
    ///
    /// # Errors
    /// As above.
    pub fn new(b: &'a [u8], tls13: bool) -> Result<Self> {
        let mm = Error::decode(r::LENGTH_MISMATCH);
        let mut rd = Reader::new(b);
        let context = if tls13 {
            Some(
                rd.vec8()
                    .or_alert(Error::decode(r::INVALID_CONTEXT))?
                    .rest(),
            )
        } else {
            None
        };
        let cert_len = usize::try_from(rd.u24().or_alert(mm)?).map_err(|_| mm)?;
        if rd.len() != cert_len {
            return Err(mm);
        }
        if cert_len == 0 {
            return Ok(Self {
                context,
                spki: None,
                rest: rd,
                expected_rest: 0,
            });
        }
        let spki_len = if tls13 {
            let n = usize::try_from(rd.u24().or_alert(mm)?).map_err(|_| mm)?;
            if n == 0 {
                return Err(Error::decode(r::EMPTY_RAW_PUBLIC_KEY));
            }
            n
        } else {
            cert_len
        };
        let spki = rd.take(spki_len).or_alert(mm)?;
        let expected_rest = cert_len.saturating_sub(3).saturating_sub(spki_len);
        Ok(Self {
            context,
            spki: Some(spki),
            rest: rd,
            expected_rest,
        })
    }

    /// TLS 1.3: the entry's extension block's contents, after the caller decoded the key. What
    /// follows the key must be exactly the rest of the entry (`SSL_R_BAD_LENGTH`), and the
    /// block must fill it (`SSL_R_LENGTH_MISMATCH`), both decode-error.
    ///
    /// # Errors
    /// As above.
    pub fn extensions(mut self) -> Result<&'a [u8]> {
        if self.rest.len() != self.expected_rest {
            return Err(Error::decode(r::BAD_LENGTH));
        }
        let mm = Error::decode(r::LENGTH_MISMATCH);
        let block = self.rest.vec16().or_alert(mm)?;
        self.rest.end().or_alert(mm)?;
        Ok(block.rest())
    }
}

impl RawPublicKey {
    /// Decodes the whole message with [`RpkReader`] (the key's DER isn't checked).
    ///
    /// # Errors
    /// As for the reader.
    pub fn parse(b: &[u8], tls13: bool) -> Result<Self> {
        let rd = RpkReader::new(b, tls13)?;
        let context = rd.context.map(<[u8]>::to_vec);
        let spki = rd.spki.map(<[u8]>::to_vec);
        let extensions = if tls13 && spki.is_some() {
            Some(rd.extensions()?.to_vec())
        } else {
            None
        };
        Ok(Self {
            context,
            spki,
            extensions,
        })
    }

    /// The body.
    ///
    /// # Errors
    /// A vector is too long.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_with(|w| {
            if let Some(c) = &self.context {
                w.vec(1, c)?;
            }
            let o = w.open(3);
            if let Some(k) = &self.spki {
                if self.context.is_some() {
                    w.vec(3, k)?;
                    w.vec(2, self.extensions.as_deref().unwrap_or_default())?;
                } else {
                    w.put(k);
                }
            }
            w.close(o)
        })
    }
}

/// A TLS 1.2 (and earlier) CertificateRequest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateRequest12 {
    /// The certificate types.
    pub certificate_types: Vec<u8>,
    /// The signature schemes (TLS 1.2), or `None` before TLS 1.2.
    pub sigalgs: Option<Vec<u16>>,
    /// The acceptable CAs' distinguished names (DER).
    pub ca_names: Vec<Vec<u8>>,
}

/// A TLS 1.3 CertificateRequest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateRequest13 {
    /// certificate_request_context.
    pub context: Vec<u8>,
    /// The extension block's contents.
    pub extensions: Vec<u8>,
}

/// A CertificateRequest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertificateRequest {
    /// TLS 1.2 and earlier.
    Tls12(CertificateRequest12),
    /// TLS 1.3.
    Tls13(CertificateRequest13),
}

impl CertificateRequest13 {
    /// The context and the extension block, as OpenSSL reads them before processing the
    /// extensions: a broken context is `SSL_R_LENGTH_MISMATCH`, a broken block
    /// `SSL_R_BAD_LENGTH`, both decode-error. What follows the block is returned for
    /// [`CertificateRequest13::check_end`], which OpenSSL makes after the extensions.
    ///
    /// # Errors
    /// As above.
    pub fn read(b: &[u8]) -> Result<(Self, &[u8])> {
        let mut rd = Reader::new(b);
        let context = rd
            .vec8()
            .or_alert(Error::decode(r::LENGTH_MISMATCH))?
            .rest()
            .to_vec();
        let extensions = rd
            .vec16()
            .or_alert(Error::decode(r::BAD_LENGTH))?
            .rest()
            .to_vec();
        Ok((
            Self {
                context,
                extensions,
            },
            rd.rest(),
        ))
    }

    /// The final check: nothing after the extension block (`SSL_R_LENGTH_MISMATCH`,
    /// decode-error).
    ///
    /// # Errors
    /// As above.
    pub fn check_end(rest: &[u8]) -> Result<()> {
        if rest.is_empty() {
            Ok(())
        } else {
            Err(Error::decode(r::LENGTH_MISMATCH))
        }
    }

    /// The extensions, split.
    ///
    /// # Errors
    /// Framing faults: `SSL_R_BAD_EXTENSION` with decode-error.
    pub fn split_extensions(&self) -> Result<Vec<Extension>> {
        ext::split(&self.extensions)
    }
}

impl CertificateRequest12 {
    /// The types and (with `sigalgs`) the signature schemes, as OpenSSL reads them before the
    /// CA names (`tls_process_certificate_request`): a broken types or schemes vector is
    /// `SSL_R_LENGTH_MISMATCH` (decode-error); an empty or odd scheme list
    /// `SSL_R_SIGNATURE_ALGORITHMS_ERROR` (internal-error alert, as OpenSSL sends). The reader
    /// is left at the CA names, which [`crate::msgs::ext::certificate_authorities::read`]
    /// reads; then [`CertificateRequest12::check_end`].
    ///
    /// # Errors
    /// As above.
    pub fn read_head(rd: &mut Reader<'_>, sigalgs: bool) -> Result<(Vec<u8>, Option<Vec<u16>>)> {
        let mm = Error::decode(r::LENGTH_MISMATCH);
        let types = rd.vec8().or_alert(mm)?.rest().to_vec();
        let schemes = if sigalgs {
            let raw = rd.vec16().or_alert(mm)?;
            Some(ext::u16_list(raw.rest()).ok_or(Error::alert(
                ad::INTERNAL_ERROR,
                r::SIGNATURE_ALGORITHMS_ERROR,
            ))?)
        } else {
            None
        };
        Ok((types, schemes))
    }

    /// The final check: nothing after the CA names (`SSL_R_LENGTH_MISMATCH`, decode-error).
    ///
    /// # Errors
    /// As above.
    pub fn check_end(rd: &Reader<'_>) -> Result<()> {
        rd.end().or_alert(Error::decode(r::LENGTH_MISMATCH))
    }
}

impl CertificateRequest {
    /// Decodes the whole message (the CA names' DER isn't checked).
    ///
    /// # Errors
    /// As for each step.
    pub fn parse(b: &[u8], tls13: bool, sigalgs: bool) -> Result<Self> {
        if tls13 {
            let (m, rest) = CertificateRequest13::read(b)?;
            CertificateRequest13::check_end(rest)?;
            return Ok(Self::Tls13(m));
        }
        let mut rd = Reader::new(b);
        let (certificate_types, sigalgs) = CertificateRequest12::read_head(&mut rd, sigalgs)?;
        let ca_names = ext::certificate_authorities::read(&mut rd)?;
        CertificateRequest12::check_end(&rd)?;
        Ok(Self::Tls12(CertificateRequest12 {
            certificate_types,
            sigalgs,
            ca_names,
        }))
    }

    /// The body.
    ///
    /// # Errors
    /// A vector is too long.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_with(|w| match self {
            Self::Tls13(m) => {
                w.vec(1, &m.context)?;
                w.vec(2, &m.extensions)
            }
            Self::Tls12(m) => {
                w.vec(1, &m.certificate_types)?;
                if let Some(s) = &m.sigalgs {
                    ext::write_u16_list(w, 2, s)?;
                }
                ext::certificate_authorities::write(w, &m.ca_names)
            }
        })
    }
}

/// A CertificateVerify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateVerify {
    /// The signature scheme (TLS 1.2 and later); `None` before.
    pub scheme: Option<u16>,
    /// The signature.
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    /// The scheme at the start of the body (`SSL_R_BAD_PACKET` with decode-error if missing),
    /// which OpenSSL checks against the peer's key before reading the signature.
    ///
    /// # Errors
    /// As above.
    pub fn scheme_of(b: &[u8]) -> Result<u16> {
        Reader::new(b).u16().or_alert(Error::decode(r::BAD_PACKET))
    }

    /// Decodes the body (`tls_process_cert_verify`): the scheme (see
    /// [`CertificateVerify::scheme_of`]), then a 2-octet-length signature filling the body
    /// (`SSL_R_LENGTH_MISMATCH`, decode-error). GOST's unprefixed signatures need a GOST
    /// provider, which the default build lacks, and aren't read here.
    ///
    /// # Errors
    /// As above.
    pub fn parse(b: &[u8], sigalgs: bool) -> Result<Self> {
        let mut rd = Reader::new(b);
        let scheme = if sigalgs {
            Some(rd.u16().or_alert(Error::decode(r::BAD_PACKET))?)
        } else {
            None
        };
        let mm = Error::decode(r::LENGTH_MISMATCH);
        let signature = rd.vec16().or_alert(mm)?.rest().to_vec();
        rd.end().or_alert(mm)?;
        Ok(Self { scheme, signature })
    }

    /// The body.
    ///
    /// # Errors
    /// The signature is too long.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_with(|w| {
            if let Some(s) = self.scheme {
                w.u16(s);
            }
            w.vec(2, &self.signature)
        })
    }
}

/// A CertificateStatus (an OCSP response), as a message in TLS 1.2 or as the status_request
/// extension's body in a TLS 1.3 Certificate entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateStatus {
    /// The OCSP response's DER.
    pub response: Vec<u8>,
}

impl CertificateStatus {
    /// Decodes the body (`tls_process_cert_status_body`): a status type other than OCSP is
    /// `SSL_R_UNSUPPORTED_STATUS_TYPE`, a response that doesn't fill the body
    /// `SSL_R_LENGTH_MISMATCH`, both decode-error.
    ///
    /// # Errors
    /// As above.
    pub fn parse(b: &[u8]) -> Result<Self> {
        let mut rd = Reader::new(b);
        let typ = rd
            .u8()
            .or_alert(Error::decode(r::UNSUPPORTED_STATUS_TYPE))?;
        if core::ffi::c_int::from(typ) != rustyssl_abi::TLSEXT_STATUSTYPE_ocsp {
            return Err(Error::decode(r::UNSUPPORTED_STATUS_TYPE));
        }
        let mm = Error::decode(r::LENGTH_MISMATCH);
        // 3.6 takes a body of only the type (no response: `response` empty), and refuses an
        // empty response (`SSL_R_BAD_PACKET`).
        if rd.end().is_ok() {
            return Ok(Self {
                response: Vec::new(),
            });
        }
        let response = rd.vec24().or_alert(mm)?.rest().to_vec();
        rd.end().or_alert(mm)?;
        if response.is_empty() {
            return Err(Error::decode(r::BAD_PACKET));
        }
        Ok(Self { response })
    }

    /// The body.
    ///
    /// # Errors
    /// The response is too long.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_with(|w| {
            w.u8(1);
            w.vec(3, &self.response)
        })
    }
}

/// A CompressedCertificate (RFC 8879).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressedCertificate {
    /// The compression algorithm.
    pub algorithm: u16,
    /// The length the Certificate message decompresses to.
    pub uncompressed_length: u32,
    /// The declared length of the compressed data.
    pub compressed_length: u32,
    /// The compressed data (everything after the lengths).
    pub compressed: Vec<u8>,
}

impl CompressedCertificate {
    /// The algorithm at the start of the body (bad-certificate with `ERR_R_INTERNAL_ERROR` if
    /// missing, as OpenSSL reports it), which OpenSSL checks before the rest.
    ///
    /// # Errors
    /// As above.
    pub fn algorithm_of(b: &[u8]) -> Result<u16> {
        Reader::new(b).u16().or_alert(compressed_alg_missing())
    }

    /// The algorithm and both lengths (`tls13_process_compressed_certificate`): missing
    /// lengths are `SSL_R_BAD_DECOMPRESSION` with bad-certificate. The caller checks the
    /// algorithm and the uncompressed length against its limit, then calls
    /// [`CompressedCertificate::check`].
    ///
    /// # Errors
    /// As above.
    pub fn parse(b: &[u8]) -> Result<Self> {
        let mut rd = Reader::new(b);
        let algorithm = rd.u16().or_alert(compressed_alg_missing())?;
        let e = Error::alert(ad::BAD_CERTIFICATE, r::BAD_DECOMPRESSION);
        let uncompressed_length = rd.u24().or_alert(e)?;
        let compressed_length = rd.u24().or_alert(e)?;
        Ok(Self {
            algorithm,
            uncompressed_length,
            compressed_length,
            compressed: rd.rest().to_vec(),
        })
    }

    /// The compressed data must be exactly its declared, non-zero length
    /// (`SSL_R_BAD_DECOMPRESSION` with decode-error).
    ///
    /// # Errors
    /// As above.
    pub fn check(&self) -> Result<()> {
        let n = u32::try_from(self.compressed.len()).ok();
        if n != Some(self.compressed_length) || self.compressed_length == 0 {
            return Err(Error::decode(r::BAD_DECOMPRESSION));
        }
        Ok(())
    }

    /// The body.
    ///
    /// # Errors
    /// Never.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_with(|w| {
            w.u16(self.algorithm);
            w.u24(self.uncompressed_length);
            w.u24(self.compressed_length);
            w.put(&self.compressed);
            Ok(())
        })
    }
}

/// The error for a CompressedCertificate without an algorithm.
const fn compressed_alg_missing() -> Error {
    Error::alert_lib(ad::BAD_CERTIFICATE, rustyssl_abi::ERR_R_INTERNAL_ERROR)
}
