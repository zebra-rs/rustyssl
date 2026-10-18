//! TLS 1.2 and earlier's key exchange messages: ServerKeyExchange and ClientKeyExchange.
//!
//! Their contents depend on the key exchange, and OpenSSL reads them in steps with checks of the
//! connection in between (the group offered, the key's size, the signature algorithm), so each
//! step is a function on a [`Reader`] here, used in OpenSSL's order (`tls_process_key_exchange`,
//! `tls_process_client_key_exchange`); [`ServerKeyExchange::parse`] and
//! [`ClientKeyExchange::parse`] run every step for the codec's own tests and the fuzzer.

use crate::codec::Reader;
use crate::consts::MAX_PSK_IDENTITY_LEN;
use crate::error::{Error, Result};
use crate::msgs::{OrAlert, ad, encode_with, r};

/// The key exchange method (the cipher suite's `SSL_k*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KxMethod {
    /// None chosen (TLS 1.3, or not yet known).
    #[default]
    None,
    /// RSA key transport.
    Rsa,
    /// Ephemeral finite-field Diffie-Hellman.
    Dhe,
    /// Ephemeral elliptic-curve Diffie-Hellman.
    Ecdhe,
    /// Plain PSK.
    Psk,
    /// RSA key transport with a PSK.
    RsaPsk,
    /// DHE with a PSK.
    DhePsk,
    /// ECDHE with a PSK.
    EcdhePsk,
    /// SRP.
    Srp,
    /// GOST (needs a GOST provider; its messages are kept raw).
    Gost,
}

impl KxMethod {
    /// Whether the messages start with the PSK identity (hint).
    #[must_use]
    pub const fn has_psk(self) -> bool {
        matches!(
            self,
            Self::Psk | Self::RsaPsk | Self::DhePsk | Self::EcdhePsk
        )
    }
}

/// The key exchange, as decoding its messages needs it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Kx {
    /// The method.
    pub method: KxMethod,
    /// Whether the ServerKeyExchange is signed (the suite authenticates with a certificate).
    pub signed: bool,
    /// Whether the version is SSL 3.0 (RSA's ClientKeyExchange then has no length).
    pub ssl3: bool,
}

/// The parameters a ServerKeyExchange carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerParams {
    /// No parameters beyond the PSK hint (PSK, RSA-PSK).
    None,
    /// DHE: the prime, the generator, and the server's public value.
    Dhe {
        /// p.
        p: Vec<u8>,
        /// g.
        g: Vec<u8>,
        /// Ys.
        ys: Vec<u8>,
    },
    /// ECDHE: the curve type (3, named_curve), the group, and the server's point.
    Ecdhe {
        /// The curve type.
        curve_type: u8,
        /// The group.
        group: u16,
        /// The encoded point.
        point: Vec<u8>,
    },
    /// SRP: N, g, the salt, and B.
    Srp {
        /// N.
        n: Vec<u8>,
        /// g.
        g: Vec<u8>,
        /// The salt.
        s: Vec<u8>,
        /// B.
        b: Vec<u8>,
    },
    /// GOST and unknown methods: the body as received.
    Raw(Vec<u8>),
}

/// A ServerKeyExchange's signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkeSignature {
    /// The signature scheme (TLS 1.2); `None` before.
    pub scheme: Option<u16>,
    /// The signature.
    pub signature: Vec<u8>,
}

/// A ServerKeyExchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerKeyExchange {
    /// The PSK identity hint (with a PSK method).
    pub psk_hint: Option<Vec<u8>>,
    /// The parameters.
    pub params: ServerParams,
    /// The signature, for a signed exchange.
    pub signature: Option<SkeSignature>,
}

/// The ServerKeyExchange steps.
pub mod ske {
    use super::*;

    /// The PSK identity hint (`tls_process_ske_psk_preamble`): a broken vector is
    /// `SSL_R_LENGTH_MISMATCH` (decode-error), a hint over 256 octets
    /// `SSL_R_DATA_LENGTH_TOO_LONG` (handshake-failure).
    ///
    /// # Errors
    /// As above.
    pub fn psk_hint(rd: &mut Reader<'_>) -> Result<Vec<u8>> {
        let hint = rd.vec16().or_alert(Error::decode(r::LENGTH_MISMATCH))?;
        if hint.len() > MAX_PSK_IDENTITY_LEN {
            return Err(Error::alert(ad::HANDSHAKE_FAILURE, r::DATA_LENGTH_TOO_LONG));
        }
        Ok(hint.rest().to_vec())
    }

    /// SRP's parameters (`tls_process_ske_srp`): any broken vector is `SSL_R_LENGTH_MISMATCH`
    /// with decode-error.
    ///
    /// # Errors
    /// As above.
    pub fn srp(rd: &mut Reader<'_>) -> Result<ServerParams> {
        let mm = Error::decode(r::LENGTH_MISMATCH);
        let n = rd.vec16().or_alert(mm)?.rest().to_vec();
        let g = rd.vec16().or_alert(mm)?.rest().to_vec();
        let s = rd.vec8().or_alert(mm)?.rest().to_vec();
        let b = rd.vec16().or_alert(mm)?.rest().to_vec();
        Ok(ServerParams::Srp { n, g, s, b })
    }

    /// DHE's parameters (`tls_process_ske_dhe`): any broken vector is
    /// `SSL_R_LENGTH_MISMATCH` with decode-error.
    ///
    /// # Errors
    /// As above.
    pub fn dhe(rd: &mut Reader<'_>) -> Result<ServerParams> {
        let mm = Error::decode(r::LENGTH_MISMATCH);
        let p = rd.vec16().or_alert(mm)?.rest().to_vec();
        let g = rd.vec16().or_alert(mm)?.rest().to_vec();
        let ys = rd.vec16().or_alert(mm)?.rest().to_vec();
        Ok(ServerParams::Dhe { p, g, ys })
    }

    /// ECDHE's curve type and group (`tls_process_ske_ecdhe`): missing octets are
    /// `SSL_R_LENGTH_TOO_SHORT` (decode-error). OpenSSL then rejects a type other than
    /// named_curve, or a group the client didn't offer, with `SSL_R_WRONG_CURVE`
    /// (illegal-parameter); [`ecdhe_type_ok`] makes the first check.
    ///
    /// # Errors
    /// As above.
    pub fn ecdhe_group(rd: &mut Reader<'_>) -> Result<(u8, u16)> {
        let e = Error::decode(r::LENGTH_TOO_SHORT);
        let t = rd.u8().or_alert(e)?;
        let g = rd.u16().or_alert(e)?;
        Ok((t, g))
    }

    /// The curve-type check: named_curve (3), else `SSL_R_WRONG_CURVE` with
    /// illegal-parameter.
    ///
    /// # Errors
    /// As above.
    pub fn ecdhe_type_ok(curve_type: u8) -> Result<()> {
        if curve_type == 3 {
            Ok(())
        } else {
            Err(Error::alert(ad::ILLEGAL_PARAMETER, r::WRONG_CURVE))
        }
    }

    /// ECDHE's point: a 1-octet-length vector (`SSL_R_LENGTH_MISMATCH`, decode-error).
    ///
    /// # Errors
    /// As above.
    pub fn ecdhe_point(rd: &mut Reader<'_>) -> Result<Vec<u8>> {
        Ok(rd
            .vec8()
            .or_alert(Error::decode(r::LENGTH_MISMATCH))?
            .rest()
            .to_vec())
    }

    /// TLS 1.2's signature scheme (`SSL_R_LENGTH_TOO_SHORT` with decode-error if missing).
    ///
    /// # Errors
    /// As above.
    pub fn sigalg(rd: &mut Reader<'_>) -> Result<u16> {
        rd.u16().or_alert(Error::decode(r::LENGTH_TOO_SHORT))
    }

    /// The signature: a 2-octet-length vector filling the rest (`SSL_R_LENGTH_MISMATCH`,
    /// decode-error).
    ///
    /// # Errors
    /// As above.
    pub fn signature(rd: &mut Reader<'_>) -> Result<Vec<u8>> {
        let mm = Error::decode(r::LENGTH_MISMATCH);
        let s = rd.vec16().or_alert(mm)?.rest().to_vec();
        rd.end().or_alert(mm)?;
        Ok(s)
    }

    /// An unsigned exchange's end: nothing may follow the parameters
    /// (`SSL_R_EXTRA_DATA_IN_MESSAGE`, decode-error).
    ///
    /// # Errors
    /// As above.
    pub fn end_unsigned(rd: &Reader<'_>) -> Result<()> {
        rd.end().or_alert(Error::decode(r::EXTRA_DATA_IN_MESSAGE))
    }
}

impl ServerKeyExchange {
    /// Decodes the whole body, running the steps in OpenSSL's order; the octets the signature
    /// covers are [`ServerKeyExchange::signed_params`].
    ///
    /// # Errors
    /// As for each step; a method that has no ServerKeyExchange (RSA) is
    /// `SSL_R_UNEXPECTED_MESSAGE` with unexpected-message.
    pub fn parse(b: &[u8], kx: Kx, sigalgs: bool) -> Result<Self> {
        let mut rd = Reader::new(b);
        let psk_hint = if kx.method.has_psk() {
            Some(ske::psk_hint(&mut rd)?)
        } else {
            None
        };
        let params = match kx.method {
            KxMethod::Psk | KxMethod::RsaPsk => ServerParams::None,
            KxMethod::Srp => ske::srp(&mut rd)?,
            KxMethod::Dhe | KxMethod::DhePsk => ske::dhe(&mut rd)?,
            KxMethod::Ecdhe | KxMethod::EcdhePsk => {
                let (curve_type, group) = ske::ecdhe_group(&mut rd)?;
                ske::ecdhe_type_ok(curve_type)?;
                ServerParams::Ecdhe {
                    curve_type,
                    group,
                    point: ske::ecdhe_point(&mut rd)?,
                }
            }
            KxMethod::Gost | KxMethod::None => ServerParams::Raw(rd.take_rest().to_vec()),
            KxMethod::Rsa => {
                return Err(Error::alert(
                    rustyssl_abi::SSL_AD_UNEXPECTED_MESSAGE,
                    r::UNEXPECTED_MESSAGE,
                ));
            }
        };
        let signature = if kx.signed {
            let scheme = if sigalgs {
                Some(ske::sigalg(&mut rd)?)
            } else {
                None
            };
            Some(SkeSignature {
                scheme,
                signature: ske::signature(&mut rd)?,
            })
        } else {
            ske::end_unsigned(&rd)?;
            None
        };
        Ok(Self {
            psk_hint,
            params,
            signature,
        })
    }

    /// The parameters' encoding (what the signature covers, after the two randoms).
    ///
    /// # Errors
    /// A vector is too long.
    pub fn signed_params(&self) -> Result<Vec<u8>> {
        encode_with(|w| {
            if let Some(h) = &self.psk_hint {
                w.vec(2, h)?;
            }
            match &self.params {
                ServerParams::None => Ok(()),
                ServerParams::Dhe { p, g, ys } => {
                    w.vec(2, p)?;
                    w.vec(2, g)?;
                    w.vec(2, ys)
                }
                ServerParams::Ecdhe {
                    curve_type,
                    group,
                    point,
                } => {
                    w.u8(*curve_type);
                    w.u16(*group);
                    w.vec(1, point)
                }
                ServerParams::Srp { n, g, s, b } => {
                    w.vec(2, n)?;
                    w.vec(2, g)?;
                    w.vec(1, s)?;
                    w.vec(2, b)
                }
                ServerParams::Raw(b) => {
                    w.put(b);
                    Ok(())
                }
            }
        })
    }

    /// The body.
    ///
    /// # Errors
    /// A vector is too long.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = self.signed_params()?;
        if let Some(sig) = &self.signature {
            let tail = encode_with(|w| {
                if let Some(s) = sig.scheme {
                    w.u16(s);
                }
                w.vec(2, &sig.signature)
            })?;
            out.extend_from_slice(&tail);
        }
        Ok(out)
    }
}

/// A ClientKeyExchange, kept as received; the steps below read it for each method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientKeyExchange {
    /// The body.
    pub body: Vec<u8>,
    /// The PSK identity (with a PSK method).
    pub psk_identity: Option<Vec<u8>>,
    /// The method's value: RSA's encrypted premaster secret, DHE's Yc, ECDHE's point, SRP's
    /// A; for plain PSK and GOST, empty and the raw rest respectively.
    pub value: Vec<u8>,
}

/// The ClientKeyExchange steps.
pub mod cke {
    use super::*;

    /// The PSK identity (`tls_process_cke_psk_preamble`): a broken vector is
    /// `SSL_R_LENGTH_MISMATCH`, an identity over 256 octets `SSL_R_DATA_LENGTH_TOO_LONG`, both
    /// decode-error.
    ///
    /// # Errors
    /// As above.
    pub fn psk_identity(rd: &mut Reader<'_>) -> Result<Vec<u8>> {
        let id = rd.vec16().or_alert(Error::decode(r::LENGTH_MISMATCH))?;
        if id.len() > MAX_PSK_IDENTITY_LEN {
            return Err(Error::decode(r::DATA_LENGTH_TOO_LONG));
        }
        Ok(id.rest().to_vec())
    }

    /// Plain PSK's end: nothing after the identity (`SSL_R_LENGTH_MISMATCH`, decode-error).
    ///
    /// # Errors
    /// As above.
    pub fn psk_end(rd: &Reader<'_>) -> Result<()> {
        rd.end().or_alert(Error::decode(r::LENGTH_MISMATCH))
    }

    /// RSA's encrypted premaster secret (`tls_process_cke_rsa`): a 2-octet-length vector
    /// filling the rest (`SSL_R_LENGTH_MISMATCH`, decode-error), or with SSL 3.0 the rest as is.
    ///
    /// # Errors
    /// As above.
    pub fn rsa(rd: &mut Reader<'_>, ssl3: bool) -> Result<Vec<u8>> {
        if ssl3 {
            return Ok(rd.take_rest().to_vec());
        }
        let mm = Error::decode(r::LENGTH_MISMATCH);
        let v = rd.vec16().or_alert(mm)?.rest().to_vec();
        rd.end().or_alert(mm)?;
        Ok(v)
    }

    /// DHE's Yc (`tls_process_cke_dhe`): a 2-octet length that must equal the rest
    /// (`SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG`), and a non-empty value
    /// (`SSL_R_MISSING_TMP_DH_KEY`), both decode-error. OpenSSL checks its own DH key between
    /// the two (an internal error when it has none).
    ///
    /// # Errors
    /// As above.
    pub fn dhe(rd: &mut Reader<'_>) -> Result<Vec<u8>> {
        let n = rd
            .u16()
            .or_alert(Error::decode(r::DH_PUBLIC_VALUE_LENGTH_IS_WRONG))?;
        if rd.len() != usize::from(n) {
            return Err(Error::decode(r::DH_PUBLIC_VALUE_LENGTH_IS_WRONG));
        }
        if rd.is_empty() {
            return Err(Error::decode(r::MISSING_TMP_DH_KEY));
        }
        Ok(rd.take_rest().to_vec())
    }

    /// ECDHE's point (`tls_process_cke_ecdhe`): an empty body is `SSL_R_MISSING_TMP_ECDH_KEY`
    /// (handshake-failure); then a 1-octet-length point filling the rest
    /// (`SSL_R_LENGTH_MISMATCH`, decode-error).
    ///
    /// # Errors
    /// As above.
    pub fn ecdhe(rd: &mut Reader<'_>) -> Result<Vec<u8>> {
        if rd.is_empty() {
            return Err(Error::alert(ad::HANDSHAKE_FAILURE, r::MISSING_TMP_ECDH_KEY));
        }
        let mm = Error::decode(r::LENGTH_MISMATCH);
        let v = rd.vec8().or_alert(mm)?.rest().to_vec();
        rd.end().or_alert(mm)?;
        Ok(v)
    }

    /// SRP's A (`tls_process_cke_srp`): a 2-octet-length vector (`SSL_R_BAD_SRP_A_LENGTH`,
    /// decode-error); OpenSSL ignores octets after it.
    ///
    /// # Errors
    /// As above.
    pub fn srp(rd: &mut Reader<'_>) -> Result<Vec<u8>> {
        Ok(rd
            .vec16()
            .or_alert(Error::decode(r::BAD_SRP_A_LENGTH))?
            .rest()
            .to_vec())
    }
}

impl ClientKeyExchange {
    /// Decodes the body for `kx`, running the steps in OpenSSL's order.
    ///
    /// # Errors
    /// As for each step.
    pub fn parse(b: &[u8], kx: Kx) -> Result<Self> {
        let mut rd = Reader::new(b);
        let psk_identity = if kx.method.has_psk() {
            Some(cke::psk_identity(&mut rd)?)
        } else {
            None
        };
        let value = match kx.method {
            KxMethod::Psk => {
                cke::psk_end(&rd)?;
                Vec::new()
            }
            KxMethod::Rsa | KxMethod::RsaPsk => cke::rsa(&mut rd, kx.ssl3)?,
            KxMethod::Dhe | KxMethod::DhePsk => cke::dhe(&mut rd)?,
            KxMethod::Ecdhe | KxMethod::EcdhePsk => cke::ecdhe(&mut rd)?,
            KxMethod::Srp => cke::srp(&mut rd)?,
            KxMethod::Gost | KxMethod::None => rd.take_rest().to_vec(),
        };
        Ok(Self {
            body: b.to_vec(),
            psk_identity,
            value,
        })
    }

    /// A ClientKeyExchange's body for `kx`, from the PSK identity (with a PSK method) and the
    /// method's value.
    ///
    /// # Errors
    /// A vector is too long.
    pub fn build(kx: Kx, psk_identity: Option<&[u8]>, value: &[u8]) -> Result<Self> {
        let body = encode_with(|w| {
            if let Some(id) = psk_identity {
                w.vec(2, id)?;
            }
            match kx.method {
                KxMethod::Psk => Ok(()),
                KxMethod::Rsa | KxMethod::RsaPsk if kx.ssl3 => {
                    w.put(value);
                    Ok(())
                }
                KxMethod::Rsa
                | KxMethod::RsaPsk
                | KxMethod::Dhe
                | KxMethod::DhePsk
                | KxMethod::Srp => w.vec(2, value),
                KxMethod::Ecdhe | KxMethod::EcdhePsk => w.vec(1, value),
                KxMethod::Gost | KxMethod::None => {
                    w.put(value);
                    Ok(())
                }
            }
        })?;
        Ok(Self {
            body,
            psk_identity: psk_identity.map(<[u8]>::to_vec),
            value: value.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kx(method: KxMethod, signed: bool) -> Kx {
        Kx {
            method,
            signed,
            ssl3: false,
        }
    }

    #[test]
    fn server_key_exchanges_round_trip() {
        let m = ServerKeyExchange {
            psk_hint: None,
            params: ServerParams::Ecdhe {
                curve_type: 3,
                group: 0x17,
                point: vec![4; 65],
            },
            signature: Some(SkeSignature {
                scheme: Some(0x0804),
                signature: vec![9; 256],
            }),
        };
        let b = m.encode().unwrap();
        assert_eq!(
            ServerKeyExchange::parse(&b, kx(KxMethod::Ecdhe, true), true).unwrap(),
            m
        );
        let m = ServerKeyExchange {
            psk_hint: Some(b"hint".to_vec()),
            params: ServerParams::Dhe {
                p: vec![0xff; 256],
                g: vec![2],
                ys: vec![7; 256],
            },
            signature: None,
        };
        let b = m.encode().unwrap();
        assert_eq!(
            ServerKeyExchange::parse(&b, kx(KxMethod::DhePsk, false), true).unwrap(),
            m
        );
        let mut extra = b.clone();
        extra.push(0);
        assert_eq!(
            ServerKeyExchange::parse(&extra, kx(KxMethod::DhePsk, false), true)
                .unwrap_err()
                .reason,
            r::EXTRA_DATA_IN_MESSAGE
        );
        let srp = ServerKeyExchange {
            psk_hint: None,
            params: ServerParams::Srp {
                n: vec![1; 128],
                g: vec![2],
                s: vec![3; 16],
                b: vec![4; 128],
            },
            signature: Some(SkeSignature {
                scheme: None,
                signature: vec![5; 64],
            }),
        };
        let b = srp.encode().unwrap();
        assert_eq!(
            ServerKeyExchange::parse(&b, kx(KxMethod::Srp, true), false).unwrap(),
            srp
        );
    }

    #[test]
    fn server_key_exchange_faults() {
        let k = kx(KxMethod::Ecdhe, true);
        assert_eq!(
            ServerKeyExchange::parse(&[3, 0], k, true)
                .unwrap_err()
                .reason,
            r::LENGTH_TOO_SHORT
        );
        assert_eq!(
            ServerKeyExchange::parse(&[1, 0, 0x17, 0], k, true)
                .unwrap_err()
                .reason,
            r::WRONG_CURVE
        );
        assert_eq!(
            ServerKeyExchange::parse(&[3, 0, 0x17, 2, 1], k, true)
                .unwrap_err()
                .reason,
            r::LENGTH_MISMATCH
        );
        assert_eq!(
            ServerKeyExchange::parse(&[3, 0, 0x17, 1, 1, 8], k, true)
                .unwrap_err()
                .reason,
            r::LENGTH_TOO_SHORT
        );
        let long_hint = {
            let mut v = vec![0x01, 0x01];
            v.extend_from_slice(&[b'a'; 257]);
            v
        };
        let e = ServerKeyExchange::parse(&long_hint, kx(KxMethod::Psk, false), true).unwrap_err();
        assert_eq!((e.alert, e.reason), (Some(40), r::DATA_LENGTH_TOO_LONG));
    }

    #[test]
    fn client_key_exchanges() {
        for (method, value) in [
            (KxMethod::Rsa, vec![1u8; 256]),
            (KxMethod::Dhe, vec![2; 256]),
            (KxMethod::Ecdhe, vec![4; 65]),
            (KxMethod::Srp, vec![5; 128]),
        ] {
            let m = ClientKeyExchange::build(kx(method, false), None, &value).unwrap();
            assert_eq!(
                ClientKeyExchange::parse(&m.body, kx(method, false)).unwrap(),
                m
            );
        }
        let m =
            ClientKeyExchange::build(kx(KxMethod::EcdhePsk, false), Some(b"id"), &[4; 33]).unwrap();
        assert_eq!(
            ClientKeyExchange::parse(&m.body, kx(KxMethod::EcdhePsk, false)).unwrap(),
            m
        );
        let m = ClientKeyExchange::build(kx(KxMethod::Psk, false), Some(b"id"), &[]).unwrap();
        assert_eq!(
            ClientKeyExchange::parse(&m.body, kx(KxMethod::Psk, false)).unwrap(),
            m
        );
        let ssl3 = Kx {
            method: KxMethod::Rsa,
            signed: false,
            ssl3: true,
        };
        assert_eq!(
            ClientKeyExchange::parse(&[1, 2, 3], ssl3).unwrap().value,
            [1, 2, 3]
        );
        let k = kx(KxMethod::Dhe, false);
        assert_eq!(
            ClientKeyExchange::parse(&[0, 3, 1], k).unwrap_err().reason,
            r::DH_PUBLIC_VALUE_LENGTH_IS_WRONG
        );
        assert_eq!(
            ClientKeyExchange::parse(&[0, 0], k).unwrap_err().reason,
            r::MISSING_TMP_DH_KEY
        );
        let e = ClientKeyExchange::parse(&[], kx(KxMethod::Ecdhe, false)).unwrap_err();
        assert_eq!((e.alert, e.reason), (Some(40), r::MISSING_TMP_ECDH_KEY));
        assert_eq!(
            ClientKeyExchange::parse(&[0, 2, 1, 1, 9], kx(KxMethod::Psk, false))
                .unwrap_err()
                .reason,
            r::LENGTH_MISMATCH
        );
        assert_eq!(
            ClientKeyExchange::parse(&[0, 3, 1], kx(KxMethod::Srp, false))
                .unwrap_err()
                .reason,
            r::BAD_SRP_A_LENGTH
        );
    }
}
