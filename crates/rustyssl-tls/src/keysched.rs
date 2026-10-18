//! The key schedules: TLS 1.3's (RFC 8446, section 7) on HKDF, and TLS 1.0–1.2's PRF (RFC 2246,
//! RFC 5246, RFC 7627); the transcript hash both keep; the exporters; and the key-log lines
//! OpenSSL writes. HKDF and the PRF are built here on the provider's HMAC.

use crate::codec::Writer;
use crate::crypto::{HashAlg, Provider, Secret};
use crate::error::{Error, Result};

/// HMAC of `data` under `key`.
///
/// # Errors
/// The provider has no HMAC for `hash`.
pub fn hmac(p: &dyn Provider, hash: HashAlg, key: &[u8], data: &[&[u8]]) -> Result<Vec<u8>> {
    let mut m = p.hmac(hash, key)?;
    for d in data {
        m.update(d);
    }
    Ok(m.finish())
}

/// The hash of `data`.
///
/// # Errors
/// The provider has no such hash.
pub fn hash_of(p: &dyn Provider, hash: HashAlg, data: &[u8]) -> Result<Vec<u8>> {
    let mut h = p.hash(hash)?;
    h.update(data);
    Ok(h.current())
}

/// HKDF-Extract (RFC 5869): an empty salt is the hash's length of zeros.
///
/// # Errors
/// The provider has no HMAC for `hash`.
pub fn hkdf_extract(p: &dyn Provider, hash: HashAlg, salt: &[u8], ikm: &[u8]) -> Result<Secret> {
    let zeros = vec![0u8; hash.len()];
    let salt = if salt.is_empty() { &zeros[..] } else { salt };
    Ok(Secret::new(hmac(p, hash, salt, &[ikm])?))
}

/// HKDF-Expand (RFC 5869) to `len` octets (at most 255 hash lengths).
///
/// # Errors
/// `len` is too long, or the provider has no HMAC for `hash`.
pub fn hkdf_expand(
    p: &dyn Provider,
    hash: HashAlg,
    prk: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Secret> {
    let max = hash.len().checked_mul(255).ok_or_else(Error::internal)?;
    if len > max {
        return Err(Error::internal());
    }
    let mut m = p.hmac(hash, prk)?;
    let mut out = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < len {
        m.update(&t);
        m.update(info);
        m.update(&[counter]);
        t = m.finish();
        let need = len.saturating_sub(out.len());
        out.extend(t.iter().take(need));
        counter = counter.wrapping_add(1);
    }
    t.iter_mut().for_each(|b| *b = 0);
    Ok(Secret::new(out))
}

/// HKDF-Expand-Label (RFC 8446, section 7.1) with the `tls13 ` prefix.
///
/// # Errors
/// The label or context is too long, or the provider failed.
pub fn expand_label(
    p: &dyn Provider,
    hash: HashAlg,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Result<Secret> {
    let mut info = Writer::new();
    info.u16(u16::try_from(len).map_err(|_| Error::internal())?);
    let o = info.open(1);
    info.put(b"tls13 ");
    info.put(label);
    info.close(o).map_err(|_| Error::internal())?;
    info.vec(1, context).map_err(|_| Error::internal())?;
    hkdf_expand(p, hash, secret, info.bytes(), len)
}

/// Derive-Secret (RFC 8446, section 7.1): `label` over a transcript hash.
///
/// # Errors
/// The provider failed.
pub fn derive_secret(
    p: &dyn Provider,
    hash: HashAlg,
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
) -> Result<Secret> {
    expand_label(p, hash, secret, label, transcript_hash, hash.len())
}

/// A traffic secret's key and IV.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficKeys {
    /// The AEAD key.
    pub key: Secret,
    /// The IV (XORed with the sequence number for each record's nonce).
    pub iv: Secret,
}

/// The key and IV of a TLS 1.3 traffic secret (RFC 8446, section 7.3).
///
/// # Errors
/// The provider failed.
pub fn traffic_keys(
    p: &dyn Provider,
    hash: HashAlg,
    secret: &[u8],
    key_len: usize,
    iv_len: usize,
) -> Result<TrafficKeys> {
    Ok(TrafficKeys {
        key: expand_label(p, hash, secret, b"key", &[], key_len)?,
        iv: expand_label(p, hash, secret, b"iv", &[], iv_len)?,
    })
}

/// The next application traffic secret, for KeyUpdate (RFC 8446, section 7.2).
///
/// # Errors
/// The provider failed.
pub fn next_traffic_secret(p: &dyn Provider, hash: HashAlg, secret: &[u8]) -> Result<Secret> {
    expand_label(p, hash, secret, b"traffic upd", &[], hash.len())
}

/// The finished key of a base key (RFC 8446, section 4.4.4).
///
/// # Errors
/// The provider failed.
pub fn finished_key(p: &dyn Provider, hash: HashAlg, base_key: &[u8]) -> Result<Secret> {
    expand_label(p, hash, base_key, b"finished", &[], hash.len())
}

/// TLS 1.3's Finished verify_data: HMAC with the base key's finished key over the transcript
/// hash. Also a PSK binder, with the binder key as the base key.
///
/// # Errors
/// The provider failed.
pub fn verify_data_13(
    p: &dyn Provider,
    hash: HashAlg,
    base_key: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>> {
    let fk = finished_key(p, hash, base_key)?;
    hmac(p, hash, fk.bytes(), &[transcript_hash])
}

/// The PSK of a ticket from the resumption master secret and the ticket's nonce (RFC 8446,
/// section 4.6.1).
///
/// # Errors
/// The provider failed.
pub fn resumption_psk(
    p: &dyn Provider,
    hash: HashAlg,
    resumption_master: &[u8],
    nonce: &[u8],
) -> Result<Secret> {
    expand_label(p, hash, resumption_master, b"resumption", nonce, hash.len())
}

/// TLS 1.3's exporter (RFC 8446, section 7.5) from an exporter master secret (or the early
/// one): `len` octets for `label` and `context` (an absent context exports as an empty one, as
/// OpenSSL does).
///
/// # Errors
/// The provider failed.
pub fn export_13(
    p: &dyn Provider,
    hash: HashAlg,
    exporter_master: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Result<Secret> {
    let empty = hash_of(p, hash, &[])?;
    let secret = derive_secret(p, hash, exporter_master, label, &empty)?;
    let ctx_hash = hash_of(p, hash, context)?;
    expand_label(p, hash, secret.bytes(), b"exporter", &ctx_hash, len)
}

/// Which stage the TLS 1.3 schedule has reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Early,
    Handshake,
    Master,
}

/// The TLS 1.3 key schedule (RFC 8446, section 7.1): early secret, then handshake secret, then
/// master secret.
pub struct Schedule13 {
    hash: HashAlg,
    stage: Stage,
    secret: Secret,
}

impl core::fmt::Debug for Schedule13 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Schedule13")
            .field("hash", &self.hash)
            .field("stage", &self.stage)
            .finish_non_exhaustive()
    }
}

impl Schedule13 {
    /// The early secret from `psk` (none: zeros).
    ///
    /// # Errors
    /// The provider failed.
    pub fn new(p: &dyn Provider, hash: HashAlg, psk: Option<&[u8]>) -> Result<Self> {
        let zeros = vec![0u8; hash.len()];
        let secret = hkdf_extract(p, hash, &[], psk.unwrap_or(&zeros))?;
        Ok(Self {
            hash,
            stage: Stage::Early,
            secret,
        })
    }

    /// The hash of the cipher suite.
    #[must_use]
    pub fn hash(&self) -> HashAlg {
        self.hash
    }

    /// The current stage's secret (the early, handshake, or master secret).
    #[must_use]
    pub fn secret(&self) -> &Secret {
        &self.secret
    }

    /// A secret derived from the current stage's.
    fn derive(&self, p: &dyn Provider, label: &[u8], transcript_hash: &[u8]) -> Result<Secret> {
        derive_secret(p, self.hash, self.secret.bytes(), label, transcript_hash)
    }

    /// Fails unless the schedule is at `stage`.
    fn at(&self, stage: Stage) -> Result<()> {
        if self.stage == stage {
            Ok(())
        } else {
            Err(Error::internal())
        }
    }

    /// The binder key: `res binder` for a resumption PSK, `ext binder` for an external one.
    ///
    /// # Errors
    /// The schedule is past the early stage, or the provider failed.
    pub fn binder_key(&self, p: &dyn Provider, resumption: bool) -> Result<Secret> {
        self.at(Stage::Early)?;
        let empty = hash_of(p, self.hash, &[])?;
        self.derive(
            p,
            if resumption {
                b"res binder"
            } else {
                b"ext binder"
            },
            &empty,
        )
    }

    /// The PSK binder over the transcript hash up to the binders (RFC 8446, section 4.2.11.2).
    ///
    /// # Errors
    /// The schedule is past the early stage, or the provider failed.
    pub fn binder(
        &self,
        p: &dyn Provider,
        resumption: bool,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>> {
        let key = self.binder_key(p, resumption)?;
        verify_data_13(p, self.hash, key.bytes(), transcript_hash)
    }

    /// `c e traffic`, over the ClientHello.
    ///
    /// # Errors
    /// The schedule is past the early stage, or the provider failed.
    pub fn client_early_traffic(&self, p: &dyn Provider, hash_ch: &[u8]) -> Result<Secret> {
        self.at(Stage::Early)?;
        self.derive(p, b"c e traffic", hash_ch)
    }

    /// `e exp master`, over the ClientHello.
    ///
    /// # Errors
    /// The schedule is past the early stage, or the provider failed.
    pub fn early_exporter_master(&self, p: &dyn Provider, hash_ch: &[u8]) -> Result<Secret> {
        self.at(Stage::Early)?;
        self.derive(p, b"e exp master", hash_ch)
    }

    /// Moves to the handshake secret with the (EC)DHE or KEM secret (none: zeros, for PSK-only).
    ///
    /// # Errors
    /// The schedule is past the early stage, or the provider failed.
    pub fn into_handshake(&mut self, p: &dyn Provider, shared: Option<&[u8]>) -> Result<()> {
        self.at(Stage::Early)?;
        self.advance(p, shared)?;
        self.stage = Stage::Handshake;
        Ok(())
    }

    /// The next stage's secret: Extract(Derive-Secret(current, "derived", ""), ikm).
    fn advance(&mut self, p: &dyn Provider, ikm: Option<&[u8]>) -> Result<()> {
        let empty = hash_of(p, self.hash, &[])?;
        let derived = self.derive(p, b"derived", &empty)?;
        let zeros = vec![0u8; self.hash.len()];
        self.secret = hkdf_extract(p, self.hash, derived.bytes(), ikm.unwrap_or(&zeros))?;
        Ok(())
    }

    /// `c hs traffic`, over ClientHello..ServerHello.
    ///
    /// # Errors
    /// The schedule isn't at the handshake stage, or the provider failed.
    pub fn client_handshake_traffic(&self, p: &dyn Provider, hash_sh: &[u8]) -> Result<Secret> {
        self.at(Stage::Handshake)?;
        self.derive(p, b"c hs traffic", hash_sh)
    }

    /// `s hs traffic`, over ClientHello..ServerHello.
    ///
    /// # Errors
    /// The schedule isn't at the handshake stage, or the provider failed.
    pub fn server_handshake_traffic(&self, p: &dyn Provider, hash_sh: &[u8]) -> Result<Secret> {
        self.at(Stage::Handshake)?;
        self.derive(p, b"s hs traffic", hash_sh)
    }

    /// Moves to the master secret.
    ///
    /// # Errors
    /// The schedule isn't at the handshake stage, or the provider failed.
    pub fn into_master(&mut self, p: &dyn Provider) -> Result<()> {
        self.at(Stage::Handshake)?;
        self.advance(p, None)?;
        self.stage = Stage::Master;
        Ok(())
    }

    /// `c ap traffic`, over ClientHello..server Finished.
    ///
    /// # Errors
    /// The schedule isn't at the master stage, or the provider failed.
    pub fn client_application_traffic(&self, p: &dyn Provider, hash_sf: &[u8]) -> Result<Secret> {
        self.at(Stage::Master)?;
        self.derive(p, b"c ap traffic", hash_sf)
    }

    /// `s ap traffic`, over ClientHello..server Finished.
    ///
    /// # Errors
    /// The schedule isn't at the master stage, or the provider failed.
    pub fn server_application_traffic(&self, p: &dyn Provider, hash_sf: &[u8]) -> Result<Secret> {
        self.at(Stage::Master)?;
        self.derive(p, b"s ap traffic", hash_sf)
    }

    /// `exp master`, over ClientHello..server Finished.
    ///
    /// # Errors
    /// The schedule isn't at the master stage, or the provider failed.
    pub fn exporter_master(&self, p: &dyn Provider, hash_sf: &[u8]) -> Result<Secret> {
        self.at(Stage::Master)?;
        self.derive(p, b"exp master", hash_sf)
    }

    /// `res master`, over ClientHello..client Finished.
    ///
    /// # Errors
    /// The schedule isn't at the master stage, or the provider failed.
    pub fn resumption_master(&self, p: &dyn Provider, hash_cf: &[u8]) -> Result<Secret> {
        self.at(Stage::Master)?;
        self.derive(p, b"res master", hash_cf)
    }
}

/// The hash of a TLS 1.0–1.2 PRF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrfHash {
    /// TLS 1.0 and 1.1: P_MD5 XOR P_SHA-1 over the secret's halves.
    Md5Sha1,
    /// TLS 1.2 with a SHA-256 suite (and the default).
    Sha256,
    /// TLS 1.2 with a SHA-384 suite.
    Sha384,
}

/// P_hash (RFC 5246, section 5).
fn p_hash(
    p: &dyn Provider,
    hash: HashAlg,
    secret: &[u8],
    seed: &[u8],
    out: &mut [u8],
) -> Result<()> {
    let mut m = p.hmac(hash, secret)?;
    m.update(seed);
    let mut a = m.finish();
    let mut pos = 0usize;
    while pos < out.len() {
        m.update(&a);
        m.update(seed);
        let block = m.finish();
        for (o, b) in out.iter_mut().skip(pos).zip(&block) {
            *o ^= b;
        }
        pos = pos.saturating_add(block.len());
        m.update(&a);
        a = m.finish();
    }
    a.iter_mut().for_each(|b| *b = 0);
    Ok(())
}

/// The TLS PRF: `len` octets of PRF(secret, label, seed).
///
/// # Errors
/// The provider failed.
pub fn prf(
    p: &dyn Provider,
    hash: PrfHash,
    secret: &[u8],
    label: &[u8],
    seed: &[&[u8]],
    len: usize,
) -> Result<Secret> {
    let mut s = label.to_vec();
    for part in seed {
        s.extend_from_slice(part);
    }
    let mut out = vec![0u8; len];
    match hash {
        PrfHash::Sha256 => p_hash(p, HashAlg::Sha256, secret, &s, &mut out)?,
        PrfHash::Sha384 => p_hash(p, HashAlg::Sha384, secret, &s, &mut out)?,
        PrfHash::Md5Sha1 => {
            // S1 is the first half and S2 the second, each ceil(len/2) octets (they share the
            // middle octet when the length is odd).
            let half = secret.len().div_ceil(2);
            let s1 = secret.get(..half).ok_or_else(Error::internal)?;
            let s2 = secret
                .get(secret.len().saturating_sub(half)..)
                .ok_or_else(Error::internal)?;
            p_hash(p, HashAlg::Md5, s1, &s, &mut out)?;
            p_hash(p, HashAlg::Sha1, s2, &s, &mut out)?;
        }
    }
    Ok(Secret::new(out))
}

/// The master secret from the premaster secret and the randoms (RFC 5246, section 8.1).
///
/// # Errors
/// The provider failed.
pub fn master_secret(
    p: &dyn Provider,
    hash: PrfHash,
    pms: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> Result<Secret> {
    prf(
        p,
        hash,
        pms,
        b"master secret",
        &[client_random, server_random],
        48,
    )
}

/// The Extended Master Secret from the premaster secret and the session hash (RFC 7627).
///
/// # Errors
/// The provider failed.
pub fn extended_master_secret(
    p: &dyn Provider,
    hash: PrfHash,
    pms: &[u8],
    session_hash: &[u8],
) -> Result<Secret> {
    prf(p, hash, pms, b"extended master secret", &[session_hash], 48)
}

/// The key block (RFC 5246, section 6.3): `len` octets of client MAC key, server MAC key,
/// client key, server key, client IV, server IV.
///
/// # Errors
/// The provider failed.
pub fn key_block(
    p: &dyn Provider,
    hash: PrfHash,
    master: &[u8],
    server_random: &[u8],
    client_random: &[u8],
    len: usize,
) -> Result<Secret> {
    prf(
        p,
        hash,
        master,
        b"key expansion",
        &[server_random, client_random],
        len,
    )
}

/// The keys of a TLS 1.0–1.2 connection, split out of the key block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBlock {
    /// The client's MAC key (empty for an AEAD).
    pub client_mac: Secret,
    /// The server's MAC key (empty for an AEAD).
    pub server_mac: Secret,
    /// The client's encryption key.
    pub client_key: Secret,
    /// The server's encryption key.
    pub server_key: Secret,
    /// The client's IV (for AEADs, the fixed part of the nonce).
    pub client_iv: Secret,
    /// The server's IV.
    pub server_iv: Secret,
}

impl KeyBlock {
    /// The key block of `master`, split for MAC keys of `mac_len`, keys of `key_len`, and IVs of
    /// `iv_len` octets.
    ///
    /// # Errors
    /// The provider failed.
    #[allow(clippy::too_many_arguments, reason = "the key block's inputs")]
    pub fn new(
        p: &dyn Provider,
        hash: PrfHash,
        master: &[u8],
        server_random: &[u8],
        client_random: &[u8],
        mac_len: usize,
        key_len: usize,
        iv_len: usize,
    ) -> Result<Self> {
        let total = mac_len
            .checked_add(key_len)
            .and_then(|n| n.checked_add(iv_len))
            .and_then(|n| n.checked_mul(2))
            .ok_or_else(Error::internal)?;
        let block = key_block(p, hash, master, server_random, client_random, total)?;
        let mut r = block.bytes();
        let mut take = |n: usize| -> Result<Secret> {
            let (a, b) = r.split_at_checked(n).ok_or_else(Error::internal)?;
            r = b;
            Ok(Secret::new(a.to_vec()))
        };
        Ok(Self {
            client_mac: take(mac_len)?,
            server_mac: take(mac_len)?,
            client_key: take(key_len)?,
            server_key: take(key_len)?,
            client_iv: take(iv_len)?,
            server_iv: take(iv_len)?,
        })
    }
}

/// TLS 1.0–1.2's Finished verify_data: 12 octets of PRF(master, "client finished" or "server
/// finished", handshake hash).
///
/// # Errors
/// The provider failed.
pub fn verify_data_12(
    p: &dyn Provider,
    hash: PrfHash,
    master: &[u8],
    client: bool,
    handshake_hash: &[u8],
) -> Result<Vec<u8>> {
    let label: &[u8] = if client {
        b"client finished"
    } else {
        b"server finished"
    };
    Ok(prf(p, hash, master, label, &[handshake_hash], 12)?
        .bytes()
        .to_vec())
}

/// RFC 5705's exporter for TLS 1.0–1.2: PRF(master, label, client_random + server_random
/// [+ context length + context]).
///
/// # Errors
/// The context is longer than 65535 octets, or the provider failed.
#[allow(clippy::too_many_arguments, reason = "the exporter's inputs")]
pub fn export_12(
    p: &dyn Provider,
    hash: PrfHash,
    master: &[u8],
    label: &[u8],
    client_random: &[u8],
    server_random: &[u8],
    context: Option<&[u8]>,
    len: usize,
) -> Result<Secret> {
    let mut seed = Writer::new();
    seed.put(client_random);
    seed.put(server_random);
    if let Some(c) = context {
        seed.vec(2, c).map_err(|_| Error::internal())?;
    }
    prf(p, hash, master, label, &[seed.bytes()], len)
}

/// The handshake's transcript: buffered until the hash is known (as OpenSSL buffers before
/// the ServerHello picks the suite), then hashed; the buffer may be kept for TLS 1.2's client
/// CertificateVerify, which signs the messages themselves.
#[derive(Default)]
pub struct Transcript {
    buffer: Option<Vec<u8>>,
    hash: Option<(HashAlg, Box<dyn crate::crypto::Hash>)>,
    keep_buffer: bool,
}

impl core::fmt::Debug for Transcript {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Transcript")
            .field("buffered", &self.buffer.as_ref().map(Vec::len))
            .field("hash", &self.hash.as_ref().map(|h| h.0))
            .finish()
    }
}

/// The handshake type of the synthetic message that replaces ClientHello1 after a
/// HelloRetryRequest (RFC 8446, section 4.4.1).
const MESSAGE_HASH: u8 = 254;

impl Transcript {
    /// An empty transcript, buffering.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: Some(Vec::new()),
            hash: None,
            keep_buffer: false,
        }
    }

    /// Adds a handshake message (with its 4-octet header). A buffer kept when hashing started
    /// stays as it was (`ssl3_finish_mac` only buffers before the digest exists): it holds what
    /// a TLS 1.2 CertificateVerify signs.
    pub fn add(&mut self, msg: &[u8]) {
        if !(self.keep_buffer && self.hash.is_some())
            && let Some(b) = &mut self.buffer
        {
            b.extend_from_slice(msg);
        }
        if let Some((_, h)) = &mut self.hash {
            h.update(msg);
        }
    }

    /// Starts hashing with `alg`: what was buffered is hashed, and the buffer is dropped unless
    /// `keep_buffer` (TLS 1.2 client authentication).
    ///
    /// # Errors
    /// The provider has no such hash.
    pub fn start_hash(&mut self, p: &dyn Provider, alg: HashAlg, keep_buffer: bool) -> Result<()> {
        let mut h = p.hash(alg)?;
        if let Some(b) = &self.buffer {
            h.update(b);
        }
        self.hash = Some((alg, h));
        self.keep_buffer = keep_buffer;
        if !keep_buffer {
            self.buffer = None;
        }
        Ok(())
    }

    /// Drops the kept buffer (once client authentication is settled).
    pub fn drop_buffer(&mut self) {
        self.buffer = None;
        self.keep_buffer = false;
    }

    /// The messages so far, while they are buffered.
    #[must_use]
    pub fn buffered(&self) -> Option<&[u8]> {
        self.buffer.as_deref()
    }

    /// The hash algorithm, once started.
    #[must_use]
    pub fn alg(&self) -> Option<HashAlg> {
        self.hash.as_ref().map(|h| h.0)
    }

    /// The transcript hash so far.
    ///
    /// # Errors
    /// The hash hasn't started.
    pub fn current(&self) -> Result<Vec<u8>> {
        self.hash
            .as_ref()
            .map(|(_, h)| h.current())
            .ok_or_else(Error::internal)
    }

    /// The transcript hash of what it holds plus `extra`, leaving the transcript as it is (for
    /// a binder over a truncated ClientHello, or a CertificateVerify's context).
    ///
    /// # Errors
    /// The hash hasn't started.
    pub fn current_with(&self, extra: &[u8]) -> Result<Vec<u8>> {
        let (_, h) = self.hash.as_ref().ok_or_else(Error::internal)?;
        let mut f = h.fork();
        f.update(extra);
        Ok(f.current())
    }

    /// A copy to continue separately (TLS 1.3 post-handshake authentication keeps the
    /// transcript at the client's Finished: `tls13_save_handshake_digest_for_pha`).
    #[must_use]
    pub fn fork(&self) -> Self {
        Self {
            buffer: self.buffer.clone(),
            hash: self.hash.as_ref().map(|(a, h)| (*a, h.fork())),
            keep_buffer: self.keep_buffer,
        }
    }

    /// After a HelloRetryRequest: the transcript becomes `message_hash` with ClientHello1's
    /// hash (RFC 8446, section 4.4.1). The hash must have started (with the suite's hash), and
    /// it held only ClientHello1.
    ///
    /// # Errors
    /// The hash hasn't started, or the provider failed.
    pub fn replace_with_message_hash(&mut self, p: &dyn Provider) -> Result<()> {
        let (alg, h) = self.hash.as_ref().ok_or_else(Error::internal)?;
        let alg = *alg;
        let ch1 = h.current();
        let mut msg = vec![
            MESSAGE_HASH,
            0,
            0,
            u8::try_from(ch1.len()).map_err(|_| Error::internal())?,
        ];
        msg.extend_from_slice(&ch1);
        let mut fresh = p.hash(alg)?;
        fresh.update(&msg);
        self.hash = Some((alg, fresh));
        if let Some(b) = &mut self.buffer {
            *b = msg;
        }
        Ok(())
    }
}

/// The key-log labels OpenSSL writes (`SSL_CTX_set_keylog_callback`, NSS's format).
pub mod keylog {
    /// TLS 1.2 and earlier's master secret.
    pub const CLIENT_RANDOM: &str = "CLIENT_RANDOM";
    /// TLS 1.3's client early traffic secret.
    pub const CLIENT_EARLY_TRAFFIC_SECRET: &str = "CLIENT_EARLY_TRAFFIC_SECRET";
    /// TLS 1.3's client handshake traffic secret.
    pub const CLIENT_HANDSHAKE_TRAFFIC_SECRET: &str = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
    /// TLS 1.3's server handshake traffic secret.
    pub const SERVER_HANDSHAKE_TRAFFIC_SECRET: &str = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
    /// TLS 1.3's first client application traffic secret.
    pub const CLIENT_APPLICATION_TRAFFIC_SECRET: &str = "CLIENT_TRAFFIC_SECRET_0";
    /// TLS 1.3's first server application traffic secret.
    pub const SERVER_APPLICATION_TRAFFIC_SECRET: &str = "SERVER_TRAFFIC_SECRET_0";
    /// TLS 1.3's early exporter master secret.
    pub const EARLY_EXPORTER_SECRET: &str = "EARLY_EXPORTER_SECRET";
    /// TLS 1.3's exporter master secret.
    pub const EXPORTER_SECRET: &str = "EXPORTER_SECRET";

    /// Lowercase hex.
    fn hex(b: &[u8]) -> String {
        use core::fmt::Write as _;
        b.iter().fold(
            String::with_capacity(b.len().saturating_mul(2)),
            |mut s, x| {
                let _ = write!(s, "{x:02x}");
                s
            },
        )
    }

    /// A key-log line: `label client_random secret`, in lowercase hex, as OpenSSL's
    /// `nss_keylog_int` writes it (without a newline).
    #[must_use]
    pub fn line(label: &str, client_random: &[u8], secret: &[u8]) -> String {
        format!("{label} {} {}", hex(client_random), hex(secret))
    }

    /// The RSA key-exchange line: `RSA` with the first 8 octets of the encrypted premaster
    /// secret and the premaster secret (`ssl_log_rsa_client_key_exchange`).
    #[must_use]
    pub fn rsa_line(encrypted_pms: &[u8], pms: &[u8]) -> String {
        let head = encrypted_pms.get(..8).unwrap_or(encrypted_pms);
        format!("RSA {} {}", hex(head), hex(pms))
    }
}

#[cfg(test)]
mod tests;
