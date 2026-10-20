//! Packets (RFC 9000, section 17; RFC 9001, section 5): headers, coalesced packets in a
//! datagram, key derivation (the Initial salt and the `quic key`/`quic iv`/`quic hp`/`quic ku`
//! labels), packet and header protection, packet numbers, Retry's integrity tag, and version
//! negotiation. Nothing here keeps state across packets; the channel does.

use rustyssl_tls::codec::Reader;
use rustyssl_tls::crypto::{Aead, AeadAlg, HashAlg, Secret};
use rustyssl_tls::keysched::{expand_label, hkdf_extract};
use subtle::ConstantTimeEq;

use crate::crypto::{HeaderProtection, Provider, Suite};
use crate::error::{Error, Result};
use crate::wire::{ConnId, MAX_CID_LEN, get_varint, put_varint, put_varint_len};

/// QUIC version 1 (RFC 9000), the only version OpenSSL speaks.
pub const VERSION_1: u32 = 1;

/// The smallest datagram that may carry a client's Initial (RFC 9000, section 14.1).
pub const MIN_INITIAL_DGRAM_LEN: usize = 1200;

/// Version 1's Initial salt (RFC 9001, section 5.2).
pub const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Retry's integrity key and nonce for version 1 (RFC 9001, section 5.8).
pub const RETRY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
/// See [`RETRY_KEY_V1`].
pub const RETRY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// Retry's integrity tag length.
pub const RETRY_TAG_LEN: usize = 16;

/// The AEAD tag length of every suite QUIC uses here.
pub const TAG_LEN: usize = 16;

/// A packet's type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    VersionNegotiation,
    OneRtt,
}

/// A packet-number space (RFC 9000, section 12.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Space {
    Initial,
    Handshake,
    Application,
}

impl Space {
    /// All three, in order.
    pub const ALL: [Self; 3] = [Self::Initial, Self::Handshake, Self::Application];

    /// The space's index (0, 1, 2).
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Initial => 0,
            Self::Handshake => 1,
            Self::Application => 2,
        }
    }
}

impl PacketType {
    /// The packet-number space, for the protected types.
    #[must_use]
    pub const fn space(self) -> Option<Space> {
        match self {
            Self::Initial => Some(Space::Initial),
            Self::Handshake => Some(Space::Handshake),
            Self::ZeroRtt | Self::OneRtt => Some(Space::Application),
            Self::Retry | Self::VersionNegotiation => None,
        }
    }

    /// The long header's type bits (Initial 0, 0-RTT 1, Handshake 2, Retry 3).
    const fn long_bits(self) -> u8 {
        match self {
            Self::Initial => 0,
            Self::ZeroRtt => 1,
            Self::Handshake => 2,
            _ => 3,
        }
    }
}

/// One packet located in a datagram, its header parsed but not yet unprotected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Located<'a> {
    pub ty: PacketType,
    pub version: u32,
    pub dcid: ConnId,
    /// Long headers only.
    pub scid: ConnId,
    /// Initial: the token. Retry: the retry token. Version negotiation: the version list.
    pub token: &'a [u8],
    /// Where the packet number starts, from the packet's start (protected types).
    pub pn_offset: usize,
    /// The whole packet, as it was in the datagram.
    pub bytes: &'a [u8],
}

/// Splits off the first packet of `datagram` (RFC 9000, section 12.2). Short headers run to
/// the datagram's end and carry a destination connection ID of `short_dcid_len` octets.
///
/// # Errors
/// The header is malformed (the caller drops the rest of the datagram, as OpenSSL's demuxer
/// does).
pub fn locate(datagram: &[u8], short_dcid_len: usize) -> Result<(Located<'_>, &[u8])> {
    let bad = || Error::protocol(0, "malformed packet header");
    let mut r = Reader::new(datagram);
    let first = r.u8().map_err(|_| bad())?;
    if first & 0x80 == 0 {
        // Short header. The fixed bit must be 1 (no grease_quic_bit here, as OpenSSL).
        if first & 0x40 == 0 {
            return Err(bad());
        }
        let dcid = ConnId::new(r.take(short_dcid_len).map_err(|_| bad())?).map_err(|_| bad())?;
        let pn_offset = 1usize.saturating_add(short_dcid_len);
        return Ok((
            Located {
                ty: PacketType::OneRtt,
                version: VERSION_1,
                dcid,
                scid: ConnId::default(),
                token: &[],
                pn_offset,
                bytes: datagram,
            },
            &[],
        ));
    }
    let version = r.u32().map_err(|_| bad())?;
    let dcid_len = usize::from(r.u8().map_err(|_| bad())?);
    let dcid_b = r.take(dcid_len).map_err(|_| bad())?;
    let scid_len = usize::from(r.u8().map_err(|_| bad())?);
    let scid_b = r.take(scid_len).map_err(|_| bad())?;
    if version == 0 {
        // Version negotiation: any length IDs (up to 255) and a list of versions.
        let list = r.take_rest();
        if list.is_empty() || !list.len().is_multiple_of(4) {
            return Err(bad());
        }
        let dcid = ConnId::new(dcid_b).map_err(|_| bad())?;
        let scid = ConnId::new(scid_b).map_err(|_| bad())?;
        return Ok((
            Located {
                ty: PacketType::VersionNegotiation,
                version,
                dcid,
                scid,
                token: list,
                pn_offset: 0,
                bytes: datagram,
            },
            &[],
        ));
    }
    if dcid_len > MAX_CID_LEN || scid_len > MAX_CID_LEN {
        return Err(bad());
    }
    if first & 0x40 == 0 {
        return Err(bad());
    }
    let dcid = ConnId::new(dcid_b)?;
    let scid = ConnId::new(scid_b)?;
    if version != VERSION_1 {
        // An unknown version's packet: only the invariant fields are known (RFC 8999); the
        // caller answers with version negotiation.
        return Ok((
            Located {
                ty: PacketType::Initial,
                version,
                dcid,
                scid,
                token: &[],
                pn_offset: 0,
                bytes: datagram,
            },
            &[],
        ));
    }
    let ty = match (first >> 4) & 0x03 {
        0 => PacketType::Initial,
        1 => PacketType::ZeroRtt,
        2 => PacketType::Handshake,
        _ => PacketType::Retry,
    };
    if ty == PacketType::Retry {
        let rest = r.take_rest();
        if rest.len() < RETRY_TAG_LEN {
            return Err(bad());
        }
        let token = rest
            .get(..rest.len().saturating_sub(RETRY_TAG_LEN))
            .ok_or_else(bad)?;
        return Ok((
            Located {
                ty,
                version,
                dcid,
                scid,
                token,
                pn_offset: 0,
                bytes: datagram,
            },
            &[],
        ));
    }
    let token = if ty == PacketType::Initial {
        let n = usize::try_from(get_varint(&mut r).map_err(|_| bad())?).map_err(|_| bad())?;
        r.take(n).map_err(|_| bad())?
    } else {
        &[]
    };
    let length = usize::try_from(get_varint(&mut r).map_err(|_| bad())?).map_err(|_| bad())?;
    let pn_offset = datagram.len().checked_sub(r.len()).ok_or_else(bad)?;
    let end = pn_offset.checked_add(length).ok_or_else(bad)?;
    let bytes = datagram.get(..end).ok_or_else(bad)?;
    let rest = datagram.get(end..).ok_or_else(bad)?;
    Ok((
        Located {
            ty,
            version,
            dcid,
            scid,
            token,
            pn_offset,
            bytes,
        },
        rest,
    ))
}

/// The keys of one direction at one level: the AEAD, its IV, and header protection.
pub struct Keys {
    pub suite: Suite,
    aead: Box<dyn Aead>,
    iv: [u8; 12],
    hp: Box<dyn HeaderProtection>,
    /// The header-protection key, which every key phase keeps.
    hp_key: Secret,
    /// The traffic secret, kept for key updates (1-RTT only).
    secret: Secret,
}

impl core::fmt::Debug for Keys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keys")
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

/// The `quic key`, `quic iv`, and `quic hp` of a traffic secret.
///
/// # Errors
/// The provider failed.
pub fn derive_key_material(
    p: &dyn Provider,
    suite: Suite,
    secret: &[u8],
) -> Result<(Secret, Secret, Secret)> {
    let e = |_| Error::internal("key derivation");
    let key = expand_label(
        p,
        suite.hash,
        secret,
        b"quic key",
        &[],
        suite.aead.key_len(),
    )
    .map_err(e)?;
    let iv = expand_label(p, suite.hash, secret, b"quic iv", &[], 12).map_err(e)?;
    let hp = expand_label(p, suite.hash, secret, b"quic hp", &[], suite.hp.key_len()).map_err(e)?;
    Ok((key, iv, hp))
}

impl Keys {
    /// The keys from a traffic secret.
    ///
    /// # Errors
    /// The provider failed.
    pub fn new(p: &dyn Provider, suite: Suite, secret: &[u8]) -> Result<Self> {
        let (key, iv, hp) = derive_key_material(p, suite, secret)?;
        Self::with_hp(p, suite, secret, &key, &iv, &hp)
    }

    fn with_hp(
        p: &dyn Provider,
        suite: Suite,
        secret: &[u8],
        key: &Secret,
        iv: &Secret,
        hp: &Secret,
    ) -> Result<Self> {
        let e = |_| Error::internal("cipher");
        Ok(Self {
            suite,
            aead: p.aead(suite.aead, key.bytes()).map_err(e)?,
            iv: iv.bytes().try_into().map_err(|_| Error::internal("iv"))?,
            hp: p.header_protection(suite.hp, hp.bytes()).map_err(e)?,
            hp_key: Secret::new(hp.bytes().to_vec()),
            secret: Secret::new(secret.to_vec()),
        })
    }

    /// The next key phase's keys (RFC 9001, section 6): a new secret from `quic ku`, new
    /// AEAD key and IV, and the same header-protection key.
    ///
    /// # Errors
    /// The provider failed.
    pub fn next_phase(&self, p: &dyn Provider) -> Result<Self> {
        let e = |_| Error::internal("key update");
        let s = &self.suite;
        let next = expand_label(
            p,
            s.hash,
            self.secret.bytes(),
            b"quic ku",
            &[],
            s.hash.len(),
        )
        .map_err(e)?;
        let key =
            expand_label(p, s.hash, next.bytes(), b"quic key", &[], s.aead.key_len()).map_err(e)?;
        let iv = expand_label(p, s.hash, next.bytes(), b"quic iv", &[], 12).map_err(e)?;
        Ok(Self {
            suite: self.suite,
            aead: p.aead(s.aead, key.bytes()).map_err(e)?,
            iv: iv.bytes().try_into().map_err(|_| Error::internal("iv"))?,
            hp: p.header_protection(s.hp, self.hp_key.bytes()).map_err(e)?,
            hp_key: Secret::new(self.hp_key.bytes().to_vec()),
            secret: next,
        })
    }

    fn nonce(&self, pn: u64) -> [u8; 12] {
        let mut n = self.iv;
        let pnb = pn.to_be_bytes();
        for (d, s) in n.iter_mut().skip(4).zip(pnb) {
            *d ^= s;
        }
        n
    }
}

/// The Initial secrets for a client's destination connection ID (RFC 9001, section 5.2):
/// the client's and the server's.
///
/// # Errors
/// The provider failed.
pub fn initial_secrets(p: &dyn Provider, dcid: &[u8]) -> Result<(Secret, Secret)> {
    let e = |_| Error::internal("initial secrets");
    let initial = hkdf_extract(p, HashAlg::Sha256, &INITIAL_SALT_V1, dcid).map_err(e)?;
    let client =
        expand_label(p, HashAlg::Sha256, initial.bytes(), b"client in", &[], 32).map_err(e)?;
    let server =
        expand_label(p, HashAlg::Sha256, initial.bytes(), b"server in", &[], 32).map_err(e)?;
    Ok((client, server))
}

/// The Initial keys for a client's destination connection ID: the client's and the server's.
///
/// # Errors
/// The provider failed.
pub fn initial_keys(p: &dyn Provider, dcid: &[u8]) -> Result<(Keys, Keys)> {
    let (c, s) = initial_secrets(p, dcid)?;
    Ok((
        Keys::new(p, Suite::INITIAL, c.bytes())?,
        Keys::new(p, Suite::INITIAL, s.bytes())?,
    ))
}

/// Decodes a truncated packet number (RFC 9000, Appendix A.3).
#[must_use]
pub fn decode_pn(largest: Option<u64>, truncated: u64, pn_len: usize) -> u64 {
    let expected = largest.map_or(0, |l| l.saturating_add(1));
    let bits = u32::try_from(pn_len.saturating_mul(8)).unwrap_or(32);
    let win = 1u64.checked_shl(bits).unwrap_or(u64::MAX);
    let hwin = win / 2;
    let mask = win.wrapping_sub(1);
    let candidate = (expected & !mask) | truncated;
    if candidate.saturating_add(hwin) <= expected && candidate < (1u64 << 62).saturating_sub(win) {
        candidate.saturating_add(win)
    } else if candidate > expected.saturating_add(hwin) && candidate >= win {
        candidate.saturating_sub(win)
    } else {
        candidate
    }
}

/// The packet-number length to send `pn` with, given the largest acknowledged (RFC 9000,
/// Appendix A.2).
#[must_use]
pub fn pn_len(pn: u64, largest_acked: Option<u64>) -> usize {
    let unacked = match largest_acked {
        Some(l) => pn.saturating_sub(l),
        None => pn.saturating_add(1),
    };
    let range = unacked.saturating_mul(2);
    if range < (1 << 8) {
        1
    } else if range < (1 << 16) {
        2
    } else if range < (1 << 24) {
        3
    } else {
        4
    }
}

/// An unprotected packet: its number, key phase (1-RTT), and plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub pn: u64,
    pub key_phase: bool,
    pub payload: Vec<u8>,
}

/// Removes header protection from `pkt` (RFC 9001, section 5.4): the first octet's protected
/// bits and the packet number. Returns the packet number's length, and the header as it was
/// before protection (for the AEAD's associated data). Doesn't check the reserved bits: those
/// are checked once the packet authenticates.
///
/// # Errors
/// The packet is too short to sample.
pub fn remove_header_protection(
    hp: &dyn HeaderProtection,
    pkt: &[u8],
    pn_offset: usize,
) -> Result<(usize, Vec<u8>)> {
    let bad = || Error::protocol(0, "packet too short");
    let sample_off = pn_offset.checked_add(4).ok_or_else(bad)?;
    let sample: &[u8; 16] = pkt
        .get(sample_off..sample_off.checked_add(16).ok_or_else(bad)?)
        .ok_or_else(bad)?
        .try_into()
        .map_err(|_| bad())?;
    let mask = hp
        .mask(sample)
        .map_err(|_| Error::internal("header protection"))?;
    let [m0, m1, m2, m3, m4] = mask;
    let first = *pkt.first().ok_or_else(bad)?;
    let first = if first & 0x80 != 0 {
        first ^ (m0 & 0x0f)
    } else {
        first ^ (m0 & 0x1f)
    };
    let pn_len = usize::from(first & 0x03).saturating_add(1);
    let mut header = pkt
        .get(..pn_offset.checked_add(pn_len).ok_or_else(bad)?)
        .ok_or_else(bad)?
        .to_vec();
    if let Some(f) = header.first_mut() {
        *f = first;
    }
    for (b, m) in header.iter_mut().skip(pn_offset).zip([m1, m2, m3, m4]) {
        *b ^= m;
    }
    Ok((pn_len, header))
}

/// Unprotects `pkt` (one located packet) with `keys`, taking the largest packet number
/// received in its space so far. On success, checks the reserved bits (RFC 9000, section
/// 17.2): non-zero ones are PROTOCOL_VIOLATION.
///
/// # Errors
/// `Ok(None)` is a packet that doesn't authenticate (dropped); `Err` is a protocol error.
pub fn unprotect(
    keys: &mut Keys,
    pkt: &[u8],
    pn_offset: usize,
    largest: Option<u64>,
) -> Result<Option<Opened>> {
    let Ok((pn_len, header)) = remove_header_protection(keys.hp.as_ref(), pkt, pn_offset) else {
        return Ok(None);
    };
    let pn_bytes = header.get(pn_offset..).unwrap_or(&[]);
    let truncated = pn_bytes.iter().fold(0u64, |a, &b| (a << 8) | u64::from(b));
    let pn = decode_pn(largest, truncated, pn_len);
    let body_start = header.len();
    let mut data = pkt.get(body_start..).unwrap_or(&[]).to_vec();
    let nonce = keys.nonce(pn);
    if keys.aead.open(&nonce, &header, &mut data).is_err() {
        return Ok(None);
    }
    let first = header.first().copied().unwrap_or(0);
    let long = first & 0x80 != 0;
    let reserved = if long { first & 0x0c } else { first & 0x18 };
    if reserved != 0 {
        return Err(Error::protocol(0, "reserved header bits set"));
    }
    Ok(Some(Opened {
        pn,
        key_phase: !long && first & 0x04 != 0,
        payload: data,
    }))
}

/// What a packet to send carries in its header.
#[derive(Clone, Debug)]
pub struct Outgoing<'a> {
    pub ty: PacketType,
    pub dcid: &'a ConnId,
    /// Long headers only.
    pub scid: &'a ConnId,
    /// Initial only.
    pub token: &'a [u8],
    pub pn: u64,
    pub pn_len: usize,
    /// 1-RTT only.
    pub key_phase: bool,
}

/// The header's length for `o` with a payload of `payload_len` plaintext octets (before the
/// tag), so the caller can size the payload.
#[must_use]
pub fn header_len(o: &Outgoing<'_>, payload_len: usize) -> usize {
    if o.ty == PacketType::OneRtt {
        return 1usize.saturating_add(o.dcid.len()).saturating_add(o.pn_len);
    }
    let length = o.pn_len.saturating_add(payload_len).saturating_add(TAG_LEN);
    let length_len =
        crate::wire::varint_len(u64::try_from(length).unwrap_or(u64::MAX)).unwrap_or(8);
    let mut n = 1usize
        .saturating_add(4)
        .saturating_add(1)
        .saturating_add(o.dcid.len())
        .saturating_add(1)
        .saturating_add(o.scid.len());
    if o.ty == PacketType::Initial {
        let t = u64::try_from(o.token.len()).unwrap_or(u64::MAX);
        n = n
            .saturating_add(crate::wire::varint_len(t).unwrap_or(8))
            .saturating_add(o.token.len());
    }
    n.saturating_add(length_len).saturating_add(o.pn_len)
}

/// Protects and appends one packet: `payload` (frames, already padded so the packet can be
/// sampled: at least 4 octets of packet number and payload) under `keys`.
///
/// # Errors
/// The payload is too short to sample, a field is out of range, or the provider failed.
pub fn protect(keys: &mut Keys, o: &Outgoing<'_>, payload: &[u8], out: &mut Vec<u8>) -> Result<()> {
    if o.pn_len.saturating_add(payload.len()) < 4 || !(1..=4).contains(&o.pn_len) {
        return Err(Error::internal("payload too short to sample"));
    }
    let start = out.len();
    let pn_bits = u8::try_from(o.pn_len.saturating_sub(1)).map_err(|_| Error::internal("pn"))?;
    if o.ty == PacketType::OneRtt {
        out.push(0x40 | if o.key_phase { 0x04 } else { 0 } | pn_bits);
        out.extend_from_slice(o.dcid.as_bytes());
    } else {
        out.push(0xc0 | (o.ty.long_bits() << 4) | pn_bits);
        out.extend_from_slice(&VERSION_1.to_be_bytes());
        out.push(u8::try_from(o.dcid.len()).map_err(|_| Error::internal("cid"))?);
        out.extend_from_slice(o.dcid.as_bytes());
        out.push(u8::try_from(o.scid.len()).map_err(|_| Error::internal("cid"))?);
        out.extend_from_slice(o.scid.as_bytes());
        if o.ty == PacketType::Initial {
            put_varint(
                out,
                u64::try_from(o.token.len()).map_err(|_| Error::internal("token"))?,
            )?;
            out.extend_from_slice(o.token);
        }
        let length = o
            .pn_len
            .checked_add(payload.len())
            .and_then(|n| n.checked_add(TAG_LEN))
            .ok_or_else(|| Error::internal("length"))?;
        let length = u64::try_from(length).map_err(|_| Error::internal("length"))?;
        let l = crate::wire::varint_len(length).ok_or_else(|| Error::internal("length"))?;
        put_varint_len(out, length, l)?;
    }
    let pn_offset = out.len().saturating_sub(start);
    let pnb = o.pn.to_be_bytes();
    out.extend_from_slice(pnb.get(8usize.saturating_sub(o.pn_len)..).unwrap_or(&[]));
    let header = out.get(start..).unwrap_or(&[]).to_vec();
    let mut body = payload.to_vec();
    keys.aead
        .seal(&keys.nonce(o.pn), &header, &mut body)
        .map_err(|_| Error::internal("seal"))?;
    out.extend_from_slice(&body);
    // Header protection over the packet just written.
    let sample_off = start.saturating_add(pn_offset).saturating_add(4);
    let sample: [u8; 16] = out
        .get(sample_off..sample_off.saturating_add(16))
        .ok_or_else(|| Error::internal("sample"))?
        .try_into()
        .map_err(|_| Error::internal("sample"))?;
    let [m0, m1, m2, m3, m4] = keys.hp.mask(&sample).map_err(|_| Error::internal("hp"))?;
    let long = o.ty != PacketType::OneRtt;
    if let Some(f) = out.get_mut(start) {
        *f ^= m0 & if long { 0x0f } else { 0x1f };
    }
    let pn_start = start.saturating_add(pn_offset);
    for (b, m) in out
        .iter_mut()
        .skip(pn_start)
        .take(o.pn_len)
        .zip([m1, m2, m3, m4])
    {
        *b ^= m;
    }
    Ok(())
}

/// Retry's integrity tag (RFC 9001, section 5.8) over the Retry packet `retry` (without its
/// tag), for the client's original destination connection ID `odcid`.
///
/// # Errors
/// The provider failed.
pub fn retry_tag(p: &dyn Provider, odcid: &ConnId, retry: &[u8]) -> Result<[u8; RETRY_TAG_LEN]> {
    let mut aad = Vec::with_capacity(retry.len().saturating_add(21));
    aad.push(u8::try_from(odcid.len()).map_err(|_| Error::internal("odcid"))?);
    aad.extend_from_slice(odcid.as_bytes());
    aad.extend_from_slice(retry);
    let mut aead = p
        .aead(AeadAlg::Aes128Gcm, &RETRY_KEY_V1)
        .map_err(|_| Error::internal("retry aead"))?;
    let mut tag = Vec::new();
    aead.seal(&RETRY_NONCE_V1, &aad, &mut tag)
        .map_err(|_| Error::internal("retry tag"))?;
    tag.as_slice()
        .try_into()
        .map_err(|_| Error::internal("retry tag"))
}

/// Whether a received Retry packet's tag verifies (compared in constant time).
#[must_use]
pub fn retry_tag_valid(p: &dyn Provider, odcid: &ConnId, packet: &[u8]) -> bool {
    let Some(split) = packet.len().checked_sub(RETRY_TAG_LEN) else {
        return false;
    };
    let (body, tag) = packet.split_at(split);
    retry_tag(p, odcid, body).is_ok_and(|t| bool::from(t.ct_eq(tag)))
}

/// A Retry packet from the server's `scid` to the client's `dcid` (its source ID), carrying
/// `token`, for the client's original destination ID `odcid`. The first octet's unused bits
/// come from `random_bits`.
///
/// # Errors
/// The provider failed.
pub fn build_retry(
    p: &dyn Provider,
    odcid: &ConnId,
    dcid: &ConnId,
    scid: &ConnId,
    token: &[u8],
    random_bits: u8,
) -> Result<Vec<u8>> {
    let mut out = vec![0xf0 | (random_bits & 0x0f)];
    out.extend_from_slice(&VERSION_1.to_be_bytes());
    out.push(u8::try_from(dcid.len()).map_err(|_| Error::internal("cid"))?);
    out.extend_from_slice(dcid.as_bytes());
    out.push(u8::try_from(scid.len()).map_err(|_| Error::internal("cid"))?);
    out.extend_from_slice(scid.as_bytes());
    out.extend_from_slice(token);
    let tag = retry_tag(p, odcid, &out)?;
    out.extend_from_slice(&tag);
    Ok(out)
}

/// A version negotiation packet (RFC 9000, section 17.2.1) answering a packet from `scid` to
/// `dcid`, listing version 1. Its IDs are the client's, swapped.
///
/// # Errors
/// An ID is too long.
pub fn build_version_negotiation(dcid: &[u8], scid: &[u8], random_bits: u8) -> Result<Vec<u8>> {
    let mut out = vec![0x80 | (random_bits & 0x7f)];
    out.extend_from_slice(&0u32.to_be_bytes());
    out.push(u8::try_from(scid.len()).map_err(|_| Error::internal("cid"))?);
    out.extend_from_slice(scid);
    out.push(u8::try_from(dcid.len()).map_err(|_| Error::internal("cid"))?);
    out.extend_from_slice(dcid);
    out.extend_from_slice(&VERSION_1.to_be_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests;
