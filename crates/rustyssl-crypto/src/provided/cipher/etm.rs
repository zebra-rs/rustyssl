//! OpenSSL 3.6's AES-CBC-HMAC-SHA1-ETM, -SHA256-ETM, and -SHA512-ETM ciphers
//! (`cipher_aes_cbc_hmac_sha_etm.c` and its three `_hw.c`), which the reference offers only on
//! aarch64 with the AES and SHA instructions, as the provider does.
//!
//! Each call of `update` (or `EVP_Cipher`) is a message of its own: AES-CBC over whole blocks
//! from the IV as set (the reference's assembly doesn't update the running IV, so the IV stays
//! as set and a second call starts from it again), and HMAC over that call's ciphertext. An
//! encryption leaves the HMAC as the tag to get; a decryption checks it, in constant time,
//! against the expected tag's first octets. The HMAC continues from the MAC key's padded
//! blocks as the reference's assembly does, counting one block before the message: without a
//! MAC key that is the hash's initial state.
//!
//! Unlike the reference, a decryption whose tag doesn't match writes no plaintext
//! (docs/DEVIATIONS.md).

use zeroize::{Zeroize, Zeroizing};

use super::{Error, Generic, Kind, Mode, Output, cbc};
use crate::lowlevel::hash::{MD32_BLOCK, Md32, Md32Kind, Sha512};
use crate::provided::aead::{Io, Raised, ct_eq};

/// The largest tag, and the room for an expected one (`AES_CBC_MAX_HMAC_SIZE`).
pub const MAX_TAG: usize = 64;
/// SHA-512's block.
const SHA512_BLOCK: usize = 128;
/// AES's block.
const AES_BLOCK: usize = 16;

/// The hash under the HMAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hash {
    Sha1,
    Sha256,
    Sha512,
}

impl Hash {
    /// The digest's length.
    const fn len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// The block's length.
    const fn block(self) -> usize {
        match self {
            Self::Sha1 | Self::Sha256 => MD32_BLOCK,
            Self::Sha512 => SHA512_BLOCK,
        }
    }

    /// The initial chaining state.
    fn initial(self) -> Chain {
        match self {
            Self::Sha1 => Chain::Md32(Md32::sha1().h),
            Self::Sha256 => Chain::Md32(Md32::sha256().h),
            Self::Sha512 => Chain::Sha512(sha512().h),
        }
    }

    /// The low-level kind of an MD32 hash.
    fn md32(self) -> Md32Kind {
        if self == Self::Sha1 {
            Md32Kind::Sha1
        } else {
            Md32Kind::Sha256
        }
    }

    /// The hash of `data` continued from `chain`, counting `prefix` octets before it, into
    /// `out` (its first [`Hash::len`] octets).
    fn finish_from(self, chain: &Chain, prefix: usize, data: &[u8], out: &mut [u8]) {
        match chain {
            Chain::Md32(h) => {
                let bits = u64::try_from(prefix).unwrap_or(0).wrapping_mul(8);
                let mut c = Md32::sha1();
                c.h = *h;
                c.nl = u32::try_from(bits & 0xffff_ffff).unwrap_or(0);
                c.nh = u32::try_from(bits >> 32).unwrap_or(0);
                // A context made here, so it's never corrupt.
                let _ = c.update(self.md32(), data);
                let _ = c.finish(self.md32());
                c.output(self.md32(), out);
                c.h.zeroize();
            }
            Chain::Sha512(h) => {
                let mut c = sha512();
                c.h = *h;
                c.nl = u64::try_from(prefix).unwrap_or(0).wrapping_mul(8);
                let _ = c.update(data);
                let _ = c.finish();
                c.output(out);
                c.h.zeroize();
            }
        }
    }

    /// The chaining state after one block, from the initial state.
    fn after_block(self, block: &[u8]) -> Chain {
        match self {
            Self::Sha1 | Self::Sha256 => {
                let mut c = if self == Self::Sha1 {
                    Md32::sha1()
                } else {
                    Md32::sha256()
                };
                let _ = c.update(self.md32(), block);
                Chain::Md32(c.h)
            }
            Self::Sha512 => {
                let mut c = sha512();
                let _ = c.update(block);
                Chain::Sha512(c.h)
            }
        }
    }

    /// The plain hash of `data` into `out`.
    fn digest(self, data: &[u8], out: &mut [u8]) {
        self.finish_from(&self.initial(), 0, data, out);
    }
}

/// A fresh SHA-512 context (`SHA512_Init`).
fn sha512() -> Sha512 {
    let mut c = Sha512 {
        h: [0; 8],
        nl: 0,
        nh: 0,
        data: [0; SHA512_BLOCK],
        num: 0,
    };
    c.init_sha512();
    c
}

/// A hash's chaining words.
#[derive(Clone)]
enum Chain {
    Md32([u32; 8]),
    Sha512([u64; 8]),
}

impl Drop for Chain {
    fn drop(&mut self) {
        match self {
            Self::Md32(h) => h.zeroize(),
            Self::Sha512(h) => h.zeroize(),
        }
    }
}

/// The MAC state and the tags (`PROV_AES_HMAC_SHA_ETM_CTX` beyond the generic context).
#[derive(Clone)]
pub(super) struct Etm {
    hash: Hash,
    /// The inner pad's state (`head`).
    head: Chain,
    /// The outer pad's state (`tail`).
    tail: Chain,
    /// The last encryption's (or decryption's) HMAC (`tag`).
    tag: Zeroizing<[u8; MAX_TAG]>,
    /// The expected tag (`exp_tag`), its first `taglen` octets set.
    expected: [u8; MAX_TAG],
    taglen: usize,
}

impl Etm {
    /// The state of a new context of `kind`, or `None` for the other ciphers.
    pub(super) fn new(kind: Kind) -> Option<Self> {
        let Kind::Block { mode, .. } = kind else {
            return None;
        };
        let hash = match mode {
            Mode::CbcHmacSha1Etm => Hash::Sha1,
            Mode::CbcHmacSha256Etm => Hash::Sha256,
            Mode::CbcHmacSha512Etm => Hash::Sha512,
            _ => return None,
        };
        Some(Self {
            hash,
            head: hash.initial(),
            tail: hash.initial(),
            tag: Zeroizing::new([0; MAX_TAG]),
            expected: [0; MAX_TAG],
            taglen: 0,
        })
    }

    /// The key schedule's reset (`init_key`): no MAC key.
    pub(super) fn reset_mac_key(&mut self) {
        self.head = self.hash.initial();
        self.tail = self.hash.initial();
    }

    /// `init_mac_key`: HMAC's padded key blocks, the key hashed first if it's longer than a
    /// block.
    fn set_mac_key(&mut self, key: &[u8]) {
        let block = self.hash.block();
        let mut k = Zeroizing::new([0u8; SHA512_BLOCK]);
        let pad = k.get_mut(..block).unwrap_or_default();
        if key.len() > block {
            self.hash.digest(key, pad);
        } else if let Some(to) = pad.get_mut(..key.len()) {
            to.copy_from_slice(key);
        }
        for b in pad.iter_mut() {
            *b ^= 0x36;
        }
        self.head = self.hash.after_block(pad);
        for b in pad.iter_mut() {
            *b ^= 0x36 ^ 0x5c;
        }
        self.tail = self.hash.after_block(pad);
    }

    /// The HMAC of `data` into the tag, as the reference's assembly makes it.
    fn mac(&mut self, data: &[u8]) {
        let len = self.hash.len();
        let block = self.hash.block();
        let mut inner = Zeroizing::new([0u8; MAX_TAG]);
        let inner = inner.get_mut(..len).unwrap_or_default();
        self.hash.finish_from(&self.head, block, data, inner);
        let tag = self.tag.get_mut(..len).unwrap_or_default();
        self.hash.finish_from(&self.tail, block, inner, tag);
    }
}

impl Generic {
    /// The ETM state.
    fn etm_state(&mut self) -> Result<&mut Etm, Error> {
        self.etm.as_deref_mut().ok_or(Error::Internal)
    }

    /// `update` (`ossl_cipher_generic_stream_update`) and `EVP_Cipher`
    /// (`ossl_cipher_generic_cipher`): the message, or nothing for no input to `update`.
    pub(super) fn etm_process(&mut self, io: Io<'_>, one_shot: bool) -> Result<Output, Raised> {
        if !self.key_set {
            return Err(Error::NoKeySet.into());
        }
        if !one_shot && io.inl == 0 {
            return Ok(Output::new(Vec::new(), 0));
        }
        if io.outsize < io.inl {
            return Err(Error::OutputBufferTooSmall.into());
        }
        let mut data = match io.input {
            Some(input) if io.out || io.inl == 0 => input.to_vec(),
            _ => return Err(Error::Silent.into()),
        };
        if let Err(e) = self.etm_cipher(&mut data) {
            data.zeroize();
            return Err(Raised {
                first: e,
                then: Some(Error::CipherOperationFailed),
            });
        }
        let len = data.len();
        Ok(Output::new(data, len))
    }

    /// `hwaes_cbc_hmac_sha*_etm`: CBC from the IV as set, and the HMAC of the ciphertext.
    fn etm_cipher(&mut self, data: &mut [u8]) -> Result<(), Error> {
        if !data.len().is_multiple_of(AES_BLOCK) {
            return Err(Error::InvalidInputLength);
        }
        let enc = self.enc;
        let mut iv = Zeroizing::new([0u8; AES_BLOCK]);
        iv.copy_from_slice(self.iv.get(..AES_BLOCK).ok_or(Error::Internal)?);
        let cipher = self.cipher.as_ref().ok_or(Error::NoKeySet)?;
        if enc {
            cbc(cipher.as_ref(), iv.as_mut_slice(), data, true)?;
            self.etm_state()?.mac(data);
            return Ok(());
        }
        let cipher = cipher.clone_box();
        let state = self.etm_state()?;
        if state.taglen == 0 {
            return Err(Error::TagNotSet);
        }
        state.mac(data);
        let n = state.taglen;
        let ok = ct_eq(
            state.tag.get(..n).ok_or(Error::Internal)?,
            state.expected.get(..n).ok_or(Error::Internal)?,
        );
        if !ok {
            return Err(Error::InvalidTag);
        }
        cbc(cipher.as_ref(), iv.as_mut_slice(), data, false)
    }

    /// `aes_set_ctx_params`'s MAC key (`init_mac_key`); `false` for another cipher.
    pub fn etm_set_mac_key(&mut self, key: &[u8]) -> bool {
        match self.etm.as_deref_mut() {
            Some(e) => {
                e.set_mac_key(key);
                true
            }
            None => false,
        }
    }

    /// `aes_set_ctx_params`'s expected tag: its octets, at most [`MAX_TAG`], none failing with
    /// `PROV_R_INVALID_TAG`.
    pub fn etm_set_expected_tag(&mut self, tag: &[u8]) -> Result<(), Error> {
        let e = self.etm_state()?;
        if tag.is_empty() {
            return Err(Error::InvalidTag);
        }
        let to = e
            .expected
            .get_mut(..tag.len())
            .ok_or(Error::FailedToGetParameter)?;
        to.copy_from_slice(tag);
        e.taglen = tag.len();
        Ok(())
    }

    /// `aes_get_ctx_params`'s tag: its first `size` octets (of [`MAX_TAG`], what the last
    /// message left), for an encryption only.
    pub fn etm_tag(&mut self, size: usize) -> Result<&[u8], Error> {
        let enc = self.enc;
        let e = self.etm_state()?;
        if size == 0 || size > MAX_TAG || !enc {
            return Err(Error::InvalidTag);
        }
        e.tag.get(..size).ok_or(Error::Internal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provided::cipher::{Ctx, Kind, Mode};
    use crate::sym::BlockAlgorithm;

    fn kind(mode: Mode) -> Kind {
        Kind::Block {
            algorithm: BlockAlgorithm::Aes,
            key_len: 16,
            mode,
        }
    }

    /// Without a MAC key the tag continues from the hash's initial state, counting a block:
    /// the reference's tag for SHA-1 over a known ciphertext.
    #[test]
    fn a_tag_without_a_mac_key_counts_a_block() {
        let mut e = Etm::new(kind(Mode::CbcHmacSha1Etm)).unwrap();
        e.mac(b"");
        let mut plain = [0u8; 20];
        Hash::Sha1.digest(b"", &mut plain);
        assert_ne!(e.tag.get(..20).unwrap(), plain.as_slice());
    }

    /// With a MAC key, the tag is HMAC's.
    #[test]
    fn a_tag_with_a_mac_key_is_hmac() {
        // RFC 4231, test case 2's key and data, as one message.
        let mut e = Etm::new(kind(Mode::CbcHmacSha256Etm)).unwrap();
        e.set_mac_key(b"Jefe");
        e.mac(b"what do ya want for nothing?");
        let expected = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(e.tag.get(..32).unwrap(), expected.as_slice());
        let mut e = Etm::new(kind(Mode::CbcHmacSha512Etm)).unwrap();
        e.set_mac_key(b"Jefe");
        e.mac(b"what do ya want for nothing?");
        assert_eq!(e.tag.get(..4).unwrap(), [0x16, 0x4b, 0x7a, 0x7b].as_slice());
    }

    /// A decryption checks the tag, and a mismatch writes nothing.
    #[test]
    fn decryption_checks_the_tag() {
        let k = kind(Mode::CbcHmacSha1Etm);
        let mut enc = Ctx::new(k);
        enc.init(true, Some(&[1; 16]), Some(&[2; 16])).unwrap();
        let g = enc.generic_mut().unwrap();
        assert!(g.etm_set_mac_key(b"key"));
        let io = Io {
            input: Some(&[3; 32]),
            inl: 32,
            out: true,
            in_place: false,
            outsize: 32,
        };
        let ct = g.etm_process(io, false).unwrap();
        let tag = g.etm_tag(20).unwrap().to_vec();
        let mut dec = Ctx::new(k);
        dec.init(false, Some(&[1; 16]), Some(&[2; 16])).unwrap();
        let g = dec.generic_mut().unwrap();
        assert!(g.etm_set_mac_key(b"key"));
        g.etm_set_expected_tag(&tag).unwrap();
        let io = Io {
            input: Some(ct.data.as_slice()),
            ..io
        };
        assert_eq!(g.etm_process(io, false).unwrap().data.as_slice(), [3; 32]);
        let mut wrong = tag.clone();
        wrong[0] ^= 1;
        g.etm_set_expected_tag(&wrong).unwrap();
        let r = g.etm_process(io, false).unwrap_err();
        assert_eq!(r.first, Error::InvalidTag);
    }
}
