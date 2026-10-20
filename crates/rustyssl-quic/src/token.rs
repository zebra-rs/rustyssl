//! Address-validation tokens (RFC 9000, section 8.1), as OpenSSL's port makes them
//! (`quic_port.c`): a Retry token or a NEW_TOKEN token holds whether it's a Retry's, when it was
//! made, (Retry only) the client's original DCID and the Retry's SCID, and the client's address,
//! sealed with AES-256-GCM under a key the port picks at random. Retry tokens live 10 s and
//! NEW_TOKEN tokens an hour; a NEW_TOKEN token in its last tenth earns a fresh one.
//!
//! The format is ours to choose (only this port reads it); OpenSSL's fields and checks are kept.

use rustyssl_tls::codec::Reader;
use rustyssl_tls::crypto::{Aead, AeadAlg};
use zeroize::Zeroizing;

use crate::crypto::Provider;
use crate::error::{Error, Result};
use crate::time::{Duration, Time};
use crate::wire::{ConnId, MAX_CID_LEN};

/// A Retry token's lifetime (OpenSSL's `RETRY_LIFETIME`).
pub const RETRY_LIFETIME: Duration = Duration::from_millis(10_000);
/// A NEW_TOKEN token's lifetime (OpenSSL's `NEW_TOKEN_LIFETIME`).
pub const NEW_TOKEN_LIFETIME: Duration = Duration::from_millis(3_600_000);
/// The longest marshalled token (OpenSSL's `MARSHALLED_TOKEN_MAX_LEN`).
pub const MARSHALLED_TOKEN_MAX_LEN: usize = 169;
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// The longest sealed token (OpenSSL's `ENCRYPTED_TOKEN_MAX_LEN`, without the Retry tag it
/// reserves).
pub const ENCRYPTED_TOKEN_MAX_LEN: usize = MARSHALLED_TOKEN_MAX_LEN + IV_LEN + TAG_LEN;

/// What a valid token says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validated {
    /// From a Retry (else NEW_TOKEN).
    pub is_retry: bool,
    /// A Retry token's original DCID.
    pub odcid: Option<ConnId>,
    /// Whether to send the client a NEW_TOKEN on this connection.
    pub gen_new_token: bool,
}

/// A port's token key.
pub struct TokenKey {
    aead: Box<dyn Aead>,
    _key: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for TokenKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TokenKey")
    }
}

fn marshal(
    is_retry: bool,
    now: Time,
    odcid: &ConnId,
    rscid: &ConnId,
    addr: &[u8],
) -> Result<Vec<u8>> {
    let mut v = Vec::with_capacity(MARSHALLED_TOKEN_MAX_LEN);
    v.push(u8::from(is_retry));
    v.extend_from_slice(&now.0.to_be_bytes());
    let l = |n: usize| u8::try_from(n).map_err(|_| Error::internal("token field"));
    if is_retry {
        v.push(l(odcid.len())?);
        v.extend_from_slice(odcid.as_bytes());
        v.push(l(rscid.len())?);
        v.extend_from_slice(rscid.as_bytes());
    }
    if addr.is_empty() {
        return Err(Error::internal("token address"));
    }
    v.push(l(addr.len())?);
    v.extend_from_slice(addr);
    if v.len() > MARSHALLED_TOKEN_MAX_LEN {
        return Err(Error::internal("token too long"));
    }
    Ok(v)
}

struct Parsed {
    is_retry: bool,
    time: Time,
    odcid: ConnId,
    rscid: ConnId,
    addr: Vec<u8>,
}

fn parse(b: &[u8]) -> Option<Parsed> {
    let mut r = Reader::new(b);
    let is_retry = match r.u8().ok()? {
        0 => false,
        1 => true,
        _ => return None,
    };
    let t: [u8; 8] = r.take(8).ok()?.try_into().ok()?;
    let cid = |r: &mut Reader<'_>| -> Option<ConnId> {
        let n = usize::from(r.u8().ok()?);
        if n > MAX_CID_LEN {
            return None;
        }
        ConnId::new(r.take(n).ok()?).ok()
    };
    let (odcid, rscid) = if is_retry {
        (cid(&mut r)?, cid(&mut r)?)
    } else {
        (ConnId::default(), ConnId::default())
    };
    let n = usize::from(r.u8().ok()?);
    if n == 0 {
        return None;
    }
    let addr = r.take(n).ok()?.to_vec();
    if !r.is_empty() {
        return None;
    }
    Some(Parsed {
        is_retry,
        time: Time(u64::from_be_bytes(t)),
        odcid,
        rscid,
        addr,
    })
}

impl TokenKey {
    /// A fresh random key.
    ///
    /// # Errors
    /// The provider failed.
    pub fn new(p: &dyn Provider) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; 32]);
        p.random(key.as_mut(), true)
            .map_err(|_| Error::internal("token key"))?;
        let aead = p
            .aead(AeadAlg::Aes256Gcm, key.as_ref())
            .map_err(|_| Error::internal("token key"))?;
        Ok(Self { aead, _key: key })
    }

    fn seal(&mut self, p: &dyn Provider, pt: Vec<u8>) -> Result<Vec<u8>> {
        let mut iv = [0u8; IV_LEN];
        p.random(&mut iv, false)
            .map_err(|_| Error::internal("token iv"))?;
        let mut body = pt;
        self.aead
            .seal(&iv, &[], &mut body)
            .map_err(|_| Error::internal("token seal"))?;
        let mut out = iv.to_vec();
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// A Retry token for a client at `addr` whose first Initial went to `odcid`, answered by a
    /// Retry from `rscid`.
    ///
    /// # Errors
    /// A field is too long, or the provider failed.
    pub fn retry_token(
        &mut self,
        p: &dyn Provider,
        now: Time,
        addr: &[u8],
        odcid: &ConnId,
        rscid: &ConnId,
    ) -> Result<Vec<u8>> {
        let pt = marshal(true, now, odcid, rscid, addr)?;
        self.seal(p, pt)
    }

    /// A NEW_TOKEN token for a client at `addr`.
    ///
    /// # Errors
    /// The address is too long, or the provider failed.
    pub fn new_token(&mut self, p: &dyn Provider, now: Time, addr: &[u8]) -> Result<Vec<u8>> {
        let pt = marshal(false, now, &ConnId::default(), &ConnId::default(), addr)?;
        self.seal(p, pt)
    }

    /// Checks a token from an Initial sent by `addr` to `dcid` at `now` (OpenSSL's
    /// `port_validate_token`): `None` if it's invalid, expired, from elsewhere, or (Retry) for
    /// another DCID.
    pub fn validate(
        &mut self,
        token: &[u8],
        now: Time,
        addr: &[u8],
        dcid: &ConnId,
    ) -> Option<Validated> {
        if token.len() < IV_LEN.saturating_add(TAG_LEN) || token.len() > ENCRYPTED_TOKEN_MAX_LEN {
            return None;
        }
        let (iv, ct) = token.split_at(IV_LEN);
        let mut body = ct.to_vec();
        self.aead.open(iv, &[], &mut body).ok()?;
        let t = parse(&body)?;
        if now < t.time {
            return None;
        }
        let age = now.since(t.time);
        let lifetime = if t.is_retry {
            RETRY_LIFETIME
        } else {
            NEW_TOKEN_LIFETIME
        };
        // OpenSSL compares whole seconds.
        if age.0 / 1_000_000_000 > lifetime.0 / 1_000_000_000 {
            return None;
        }
        if t.addr != addr {
            return None;
        }
        if t.is_retry && t.rscid != *dcid {
            return None;
        }
        let gen_new_token =
            t.is_retry || age.0 / 1_000_000_000 > NEW_TOKEN_LIFETIME.0 / 1_000_000_000 * 9 / 10;
        Some(Validated {
            is_retry: t.is_retry,
            odcid: t.is_retry.then_some(t.odcid),
            gen_new_token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testprov::TestProvider;

    const S: u64 = 1_000_000_000;

    #[test]
    fn tokens_follow_openssl() {
        let p = TestProvider::new(b"token");
        let mut k = TokenKey::new(&p).unwrap();
        let odcid = ConnId::new(&[1; 8]).unwrap();
        let rscid = ConnId::new(&[2; 8]).unwrap();
        let addr = [127, 0, 0, 1];
        let t = k
            .retry_token(&p, Time(100 * S), &addr, &odcid, &rscid)
            .unwrap();
        assert!(t.len() <= ENCRYPTED_TOKEN_MAX_LEN);
        let v = k.validate(&t, Time(105 * S), &addr, &rscid).unwrap();
        assert_eq!(v.odcid, Some(odcid.clone()));
        assert!(v.gen_new_token);
        // Expired, elsewhere, another DCID, before its time, tampered, another key.
        assert!(k.validate(&t, Time(111 * S), &addr, &rscid).is_none());
        assert!(
            k.validate(&t, Time(105 * S), &[127, 0, 0, 2], &rscid)
                .is_none()
        );
        assert!(k.validate(&t, Time(105 * S), &addr, &odcid).is_none());
        assert!(k.validate(&t, Time(99 * S), &addr, &rscid).is_none());
        let mut bad = t.clone();
        if let Some(b) = bad.last_mut() {
            *b ^= 1;
        }
        assert!(k.validate(&bad, Time(105 * S), &addr, &rscid).is_none());
        assert!(
            TokenKey::new(&p)
                .unwrap()
                .validate(&t, Time(105 * S), &addr, &rscid)
                .is_none()
        );
        // NEW_TOKEN: an hour; a new one once 90% of it has passed.
        let n = k.new_token(&p, Time(0), &addr).unwrap();
        let v = k.validate(&n, Time(60 * S), &addr, &odcid).unwrap();
        assert!(!v.gen_new_token && !v.is_retry && v.odcid.is_none());
        assert!(
            k.validate(&n, Time(3300 * S), &addr, &odcid)
                .unwrap()
                .gen_new_token
        );
        assert!(k.validate(&n, Time(3601 * S), &addr, &odcid).is_none());
        assert!(k.validate(&[0; 10], Time(0), &addr, &odcid).is_none());
    }
}
