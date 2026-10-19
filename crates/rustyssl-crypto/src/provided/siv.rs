//! AES-SIV (RFC 5297) and AES-GCM-SIV (RFC 8452) with the semantics of their provider
//! functions: `cipher_aes_siv.c` over `crypto/modes/siv128.c`, and `cipher_aes_gcm_siv.c` with
//! its `_hw.c`.
//!
//! Both take each update with output as a whole message and each without as AAD (SIV's as
//! one more S2V string, GCM-SIV's appended), allow one encryption and one decryption per key
//! unless `speed` is set, and check the tag with `final`. CMAC, AES, and POLYVAL are the vetted
//! crates' (`mac`, `sym`); tags are compared in constant time.

use zeroize::Zeroizing;

use super::cipher::{Error, Output};
use crate::mac::{self, Mac};
use crate::sym::{self, BlockAlgorithm, BlockCipher, HashAlgorithm};

/// `SIV_LEN`, GCM-SIV's `TAG_SIZE`.
const BLOCK: usize = 16;
/// GCM-SIV's nonce (`NONCE_SIZE`).
pub const GCM_SIV_NONCE: usize = 12;
/// RFC 8452's limit on the AAD and the plaintext, 2^36 octets.
const GCM_SIV_MAX: u64 = 1 << 36;

/// Constant-time equality of two octet strings of one length.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// AES keyed with `key` (16, 24, or 32 octets).
fn aes(key: &[u8]) -> Result<Box<dyn BlockCipher>, Error> {
    sym::block_cipher(BlockAlgorithm::Aes, key, None).map_err(|_| Error::Silent)
}

/// A block cipher context that copies.
struct Keyed(Box<dyn BlockCipher>);

impl Clone for Keyed {
    fn clone(&self) -> Self {
        Self(self.0.clone_box())
    }
}

impl Keyed {
    fn encrypt(&self, b: &mut [u8; BLOCK]) -> Result<(), Error> {
        self.0.encrypt_blocks(b).map_err(|_| Error::Silent)
    }
}

// -------------------------------------------------------------------------------------------
// SIV

/// A MAC context that copies.
struct Cmac(Box<dyn Mac>);

impl Clone for Cmac {
    fn clone(&self) -> Self {
        Self(self.0.clone_box())
    }
}

/// `PROV_AES_SIV_CTX` with its `SIV128_CONTEXT`.
#[derive(Clone)]
pub struct Siv {
    /// Both keys' length.
    keylen: usize,
    enc: bool,
    /// CMAC under the first key, before any data (`mac_ctx_init`).
    mac: Option<Cmac>,
    /// The CTR key, the second.
    ctr: Option<Keyed>,
    /// S2V's running value.
    d: Zeroizing<[u8; BLOCK]>,
    tag: Zeroizing<[u8; BLOCK]>,
    /// What `final` reports: 0 after an encryption or decryption that succeeded, else -1.
    final_ret: i32,
    /// Encryptions or decryptions left: 1 after the key, -1 (any number) with `speed`.
    crypto_ok: i32,
}

/// `siv128_dbl`: doubling in GF(2^128), big-endian.
fn dbl(b: &mut [u8; BLOCK]) {
    let carry = b.first().map_or(0, |x| x >> 7);
    let mut next = 0u8;
    for x in b.iter_mut().rev() {
        let c = *x >> 7;
        *x = (*x << 1) | next;
        next = c;
    }
    if let Some(last) = b.last_mut() {
        *last ^= 0x87 & 0u8.wrapping_sub(carry);
    }
}

fn xor(a: &mut [u8; BLOCK], b: &[u8; BLOCK]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= y;
    }
}

/// AES-CTR (a 128-bit big-endian counter) from `iv` over `data` in place.
fn ctr128(key: &Keyed, iv: &[u8; BLOCK], data: &mut [u8]) -> Result<(), Error> {
    let mut counter = *iv;
    for chunk in data.chunks_mut(BLOCK) {
        let mut ks = Zeroizing::new(counter);
        key.encrypt(&mut ks)?;
        for (d, k) in chunk.iter_mut().zip(ks.iter()) {
            *d ^= k;
        }
        for c in counter.iter_mut().rev() {
            *c = c.wrapping_add(1);
            if *c != 0 {
                break;
            }
        }
    }
    Ok(())
}

impl Siv {
    /// `aes_siv_newctx`, for keys of `keylen` octets in all (32, 48, or 64). As the
    /// reference's zeroed context, it allows no message until a key is set, and `final`
    /// succeeds until a message fails.
    pub fn new(keylen: usize) -> Self {
        Self {
            keylen,
            enc: false,
            mac: None,
            ctr: None,
            d: Zeroizing::new([0; BLOCK]),
            tag: Zeroizing::new([0; BLOCK]),
            final_ret: 0,
            crypto_ok: 0,
        }
    }

    /// Both keys' length (`keylen`).
    pub fn key_len(&self) -> usize {
        self.keylen
    }

    /// Whether a key is set: the reference can't copy the context before (its CTR context
    /// isn't made).
    pub fn keyed(&self) -> bool {
        self.mac.is_some() && self.ctr.is_some()
    }

    /// Whether the context is set to encrypt.
    pub fn encrypting(&self) -> bool {
        self.enc
    }

    /// `siv_init` before the parameters: the direction, and the key if given
    /// (`ossl_siv128_init`).
    pub fn init(&mut self, enc: bool, key: Option<&[u8]>) -> Result<(), Error> {
        crate::dit::with(|| self.init_dit(enc, key))
    }

    /// [`Self::init`]'s work.
    fn init_dit(&mut self, enc: bool, key: Option<&[u8]>) -> Result<(), Error> {
        self.enc = enc;
        let Some(key) = key else {
            return Ok(());
        };
        if key.len() != self.keylen {
            return Err(Error::InvalidKeyLength);
        }
        let half = self.keylen / 2;
        let (k1, k2) = key.split_at(half);
        *self.d = [0; BLOCK];
        self.mac = None;
        self.ctr = None;
        let m = mac::cmac(aes(k1)?).map_err(|_| Error::Silent)?;
        let c = Keyed(aes(k2)?);
        let mut first = Cmac(m.clone_box());
        first.0.update(&[0; BLOCK]).map_err(|_| Error::Silent)?;
        first
            .0
            .finalize(self.d.as_mut_slice())
            .map_err(|_| Error::Silent)?;
        self.mac = Some(Cmac(m));
        self.ctr = Some(c);
        self.final_ret = -1;
        self.crypto_ok = 1;
        Ok(())
    }

    /// CMAC of the pieces, from the keyed start.
    fn cmac(&self, pieces: &[&[u8]]) -> Result<[u8; BLOCK], Error> {
        let mut m = self.mac.as_ref().ok_or(Error::Silent)?.clone();
        for p in pieces {
            m.0.update(p).map_err(|_| Error::Silent)?;
        }
        let mut out = [0u8; BLOCK];
        m.0.finalize(&mut out).map_err(|_| Error::Silent)?;
        Ok(out)
    }

    /// `ossl_siv128_aad`: one more S2V string.
    fn aad(&mut self, aad: &[u8]) -> Result<(), Error> {
        dbl(&mut self.d);
        let m = self.cmac(&[aad])?;
        xor(&mut self.d, &m);
        Ok(())
    }

    /// `siv128_do_s2v_p`: S2V's last step over the plaintext.
    fn s2v(&mut self, input: &[u8]) -> Result<[u8; BLOCK], Error> {
        self.mac.as_ref().ok_or(Error::Silent)?;
        if let Some(split) = input.len().checked_sub(BLOCK) {
            let (head, last) = input.split_at(split);
            let mut t: [u8; BLOCK] = last.try_into().map_err(|_| Error::Internal)?;
            xor(&mut t, &self.d);
            self.cmac(&[head, &t])
        } else {
            let mut t = [0u8; BLOCK];
            t.iter_mut().zip(input).for_each(|(d, s)| *d = *s);
            if let Some(b) = t.get_mut(input.len()) {
                *b = 0x80;
            }
            dbl(&mut self.d);
            xor(&mut t, &self.d);
            self.cmac(&[&t])
        }
    }

    /// The CTR IV of a tag: its two 31-bit counters' top bits cleared.
    fn ctr_iv(tag: &[u8; BLOCK]) -> [u8; BLOCK] {
        let mut q = *tag;
        for i in [8, 12] {
            if let Some(b) = q.get_mut(i) {
                *b &= 0x7f;
            }
        }
        q
    }

    /// `ossl_siv128_encrypt`.
    fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, Error> {
        self.final_ret = -1;
        if self.crypto_ok == 0 {
            return Err(Error::Silent);
        }
        self.crypto_ok = self.crypto_ok.wrapping_sub(1);
        let q = self.s2v(input)?;
        *self.tag = q;
        let mut out = input.to_vec();
        ctr128(
            self.ctr.as_ref().ok_or(Error::Silent)?,
            &Self::ctr_iv(&q),
            &mut out,
        )?;
        self.final_ret = 0;
        Ok(out)
    }

    /// `ossl_siv128_decrypt`: `Err(Some(zeros))` when the tag doesn't match.
    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, Option<Vec<u8>>> {
        self.final_ret = -1;
        if self.crypto_ok == 0 {
            return Err(None);
        }
        self.crypto_ok = self.crypto_ok.wrapping_sub(1);
        let mut out = Zeroizing::new(input.to_vec());
        let key = self.ctr.as_ref().ok_or(None)?;
        ctr128(key, &Self::ctr_iv(&self.tag), &mut out).map_err(|_| None)?;
        let t = self.s2v(&out).map_err(|_| None)?;
        if !ct_eq(&t, self.tag.as_slice()) {
            return Err(Some(vec![0; out.len()]));
        }
        self.final_ret = 0;
        Ok(out.to_vec())
    }

    /// `siv_cipher` (the update too) on `inl` octets: AAD without output, else the message;
    /// a NULL input is `final`.
    pub fn cipher(
        &mut self,
        input: Option<&[u8]>,
        inl: usize,
        out: bool,
        outsize: usize,
    ) -> Result<Output, Error> {
        crate::dit::with(|| self.cipher_dit(input, inl, out, outsize))
    }

    /// [`Self::cipher`]'s work.
    fn cipher_dit(
        &mut self,
        input: Option<&[u8]>,
        inl: usize,
        out: bool,
        outsize: usize,
    ) -> Result<Output, Error> {
        if out && outsize < inl {
            return Err(Error::OutputBufferTooSmall);
        }
        let Some(input) = input else {
            return if self.final_ret == 0 {
                Ok(Output::new(Vec::new(), inl))
            } else {
                Err(Error::Silent)
            };
        };
        let input = input.get(..inl).ok_or(Error::Silent)?;
        if !out {
            self.aad(input)?;
            return Ok(Output::new(Vec::new(), inl));
        }
        if self.enc {
            let data = self.encrypt(input)?;
            Ok(Output::new(data, inl))
        } else {
            match self.decrypt(input) {
                Ok(data) => Ok(Output::new(data, inl)),
                Err(Some(zeros)) => {
                    let mut o = Output::new(zeros, 0);
                    o.failed = Some(Error::Silent);
                    Ok(o)
                }
                Err(None) => Err(Error::Silent),
            }
        }
    }

    /// `siv_stream_final`: whether the last encryption or decryption succeeded.
    pub fn finalize(&self) -> Result<Output, Error> {
        crate::dit::with(|| self.finalize_dit())
    }

    /// [`Self::finalize`]'s work.
    fn finalize_dit(&self) -> Result<Output, Error> {
        if self.final_ret == 0 {
            Ok(Output::new(Vec::new(), 0))
        } else {
            Err(Error::Silent)
        }
    }

    /// The tag, encrypting (`tag` of exactly 16 octets).
    pub fn tag(&self, size: usize) -> Result<[u8; BLOCK], Error> {
        if !self.enc || size != BLOCK {
            return Err(Error::FailedToSetParameter);
        }
        Ok(*self.tag)
    }

    /// Sets the tag to check, decrypting (`ossl_siv128_set_tag`: exactly 16 octets).
    pub fn set_tag(&mut self, tag: &[u8]) -> Result<(), Error> {
        let t: [u8; BLOCK] = tag.try_into().map_err(|_| Error::FailedToGetParameter)?;
        *self.tag = t;
        Ok(())
    }

    /// `speed`: 1 allows any number of encryptions and decryptions, anything else one.
    pub fn set_speed(&mut self, speed: u32) {
        self.crypto_ok = if speed == 1 { -1 } else { 1 };
    }

    /// What every successful parameter call ends with: `final` fails until the next message.
    pub fn reset_final(&mut self) {
        self.final_ret = -1;
    }
}

// -------------------------------------------------------------------------------------------
// GCM-SIV

/// `PROV_AES_GCM_SIV_CTX`.
#[derive(Clone)]
pub struct GcmSiv {
    key_len: usize,
    enc: bool,
    key_gen_key: Zeroizing<[u8; 32]>,
    nonce: [u8; GCM_SIV_NONCE],
    msg_auth_key: Zeroizing<[u8; BLOCK]>,
    msg_enc: Option<Keyed>,
    /// The AAD so far (`aad`, `aad_len`).
    aad: Zeroizing<Vec<u8>>,
    tag: [u8; BLOCK],
    user_tag: [u8; BLOCK],
    have_user_tag: bool,
    generated_tag: bool,
    used_enc: bool,
    used_dec: bool,
    speed: bool,
}

impl GcmSiv {
    /// `ossl_aes_gcm_siv_newctx`, for a key of `key_len` octets. The key-generating key starts
    /// as zeros, which an init without a key derives from, as the reference's does.
    pub fn new(key_len: usize) -> Self {
        Self {
            key_len,
            enc: false,
            key_gen_key: Zeroizing::new([0; 32]),
            nonce: [0; GCM_SIV_NONCE],
            msg_auth_key: Zeroizing::new([0; BLOCK]),
            msg_enc: None,
            aad: Zeroizing::new(Vec::new()),
            tag: [0; BLOCK],
            user_tag: [0; BLOCK],
            have_user_tag: false,
            generated_tag: false,
            used_enc: false,
            used_dec: false,
            speed: false,
        }
    }

    /// The key's length.
    pub fn key_len(&self) -> usize {
        self.key_len
    }

    /// Whether the context is set to encrypt.
    pub fn encrypting(&self) -> bool {
        self.enc
    }

    /// `ossl_aes_gcm_siv_init` before the parameters: the direction, key, and nonce, then the
    /// message keys derived from them (every init, with or without a new key).
    pub fn init(&mut self, enc: bool, key: Option<&[u8]>, iv: Option<&[u8]>) -> Result<(), Error> {
        crate::dit::with(|| self.init_dit(enc, key, iv))
    }

    /// [`Self::init`]'s work.
    fn init_dit(&mut self, enc: bool, key: Option<&[u8]>, iv: Option<&[u8]>) -> Result<(), Error> {
        self.enc = enc;
        if let Some(key) = key {
            if key.len() != self.key_len {
                return Err(Error::InvalidKeyLength);
            }
            self.key_gen_key
                .get_mut(..key.len())
                .ok_or(Error::Internal)?
                .copy_from_slice(key);
        }
        if let Some(iv) = iv {
            self.nonce = iv.try_into().map_err(|_| Error::InvalidIvLength)?;
        }
        self.init_key()
    }

    /// `aes_gcm_siv_initkey`: RFC 8452's key derivation.
    fn init_key(&mut self) -> Result<(), Error> {
        let kgk = aes(self
            .key_gen_key
            .get(..self.key_len)
            .ok_or(Error::Internal)?)?;
        let mut block = [0u8; BLOCK];
        block
            .get_mut(4..)
            .ok_or(Error::Internal)?
            .copy_from_slice(&self.nonce);
        self.generated_tag = false;
        self.tag = [0; BLOCK];
        let mut counter = 0u32;
        let mut derive = |dst: &mut [u8]| -> Result<(), Error> {
            for chunk in dst.chunks_mut(8) {
                block
                    .get_mut(..4)
                    .ok_or(Error::Internal)?
                    .copy_from_slice(&counter.to_le_bytes());
                let mut out = Zeroizing::new(block);
                kgk.encrypt_blocks(out.as_mut_slice())
                    .map_err(|_| Error::Silent)?;
                chunk.copy_from_slice(out.get(..chunk.len()).ok_or(Error::Internal)?);
                counter = counter.wrapping_add(1);
            }
            Ok(())
        };
        derive(self.msg_auth_key.as_mut_slice())?;
        let mut enc_key = Zeroizing::new([0u8; 32]);
        derive(enc_key.get_mut(..self.key_len).ok_or(Error::Internal)?)?;
        self.msg_enc = Some(Keyed(aes(enc_key
            .get(..self.key_len)
            .ok_or(Error::Internal)?)?));
        self.used_enc = false;
        self.used_dec = false;
        Ok(())
    }

    /// `aes_gcm_siv_aad`: appended; an empty piece clears it.
    fn aad(&mut self, aad: &[u8]) -> Result<(), Error> {
        if aad.is_empty() {
            self.aad.clear();
            return Ok(());
        }
        let total = self.aad.len().checked_add(aad.len()).ok_or(Error::Silent)?;
        let padded = u64::try_from(total.div_ceil(BLOCK).saturating_mul(BLOCK))
            .map_err(|_| Error::Silent)?;
        if padded > GCM_SIV_MAX {
            return Err(Error::Silent);
        }
        self.aad.extend_from_slice(aad);
        Ok(())
    }

    /// POLYVAL of the AAD and `text` (each zero-padded) and their lengths, XORed with the
    /// nonce, top bit cleared, encrypted: the tag.
    fn compute_tag(&self, text: &[u8]) -> Result<[u8; BLOCK], Error> {
        let mut h = sym::universal_hash(HashAlgorithm::Polyval, self.msg_auth_key.as_slice())
            .map_err(|_| Error::Silent)?;
        h.update_padded(&self.aad);
        h.update_padded(text);
        let bits = |n: usize| u64::try_from(n).unwrap_or(0).wrapping_mul(8).to_le_bytes();
        let mut lengths = [0u8; BLOCK];
        lengths
            .get_mut(..8)
            .ok_or(Error::Internal)?
            .copy_from_slice(&bits(self.aad.len()));
        lengths
            .get_mut(8..)
            .ok_or(Error::Internal)?
            .copy_from_slice(&bits(text.len()));
        let mut s = h.finalize(&lengths);
        for (x, y) in s.iter_mut().zip(self.nonce) {
            *x ^= y;
        }
        if let Some(last) = s.last_mut() {
            *last &= 0x7f;
        }
        self.msg_enc
            .as_ref()
            .ok_or(Error::Silent)?
            .encrypt(&mut s)?;
        Ok(s)
    }

    /// `aes_gcm_siv_ctr32`: CTR with a 32-bit little-endian counter in the first four
    /// octets, from the tag with its top bit set.
    fn ctr32(&self, tag: &[u8; BLOCK], data: &mut [u8]) -> Result<(), Error> {
        let key = self.msg_enc.as_ref().ok_or(Error::Silent)?;
        let mut block = *tag;
        if let Some(last) = block.last_mut() {
            *last |= 0x80;
        }
        for chunk in data.chunks_mut(BLOCK) {
            let mut ks = Zeroizing::new(block);
            key.encrypt(&mut ks)?;
            for (d, k) in chunk.iter_mut().zip(ks.iter()) {
                *d ^= k;
            }
            let c: [u8; 4] = block
                .get(..4)
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::Internal)?;
            let next = u32::from_le_bytes(c).wrapping_add(1).to_le_bytes();
            block
                .get_mut(..4)
                .ok_or(Error::Internal)?
                .copy_from_slice(&next);
        }
        Ok(())
    }

    /// Whether a message of `len` octets is within RFC 8452's limit.
    fn in_limit(len: usize) -> bool {
        u64::try_from(len).is_ok_and(|n| n <= GCM_SIV_MAX)
    }

    /// `aes_gcm_siv_encrypt`.
    fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, Error> {
        self.generated_tag = false;
        if !self.speed && self.used_enc {
            return Err(Error::Silent);
        }
        if !Self::in_limit(input.len()) {
            return Err(Error::Silent);
        }
        let r = self.compute_tag(input).and_then(|tag| {
            self.tag = tag;
            let mut out = input.to_vec();
            self.ctr32(&tag, &mut out)?;
            Ok(out)
        });
        self.generated_tag = r.is_ok();
        self.used_enc = true;
        r
    }

    /// `aes_gcm_siv_decrypt`: the plaintext, its tag computed for `final` to check.
    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, Error> {
        self.generated_tag = false;
        if !self.speed && self.used_dec {
            return Err(Error::Silent);
        }
        if !Self::in_limit(input.len()) {
            return Err(Error::Silent);
        }
        let mut out = input.to_vec();
        let user_tag = self.user_tag;
        let r = self
            .ctr32(&user_tag, &mut out)
            .and_then(|()| self.compute_tag(&out));
        if let Ok(tag) = r {
            self.tag = tag;
        }
        self.generated_tag = r.is_ok();
        self.used_dec = true;
        r.map(|_| out)
    }

    /// `ossl_aes_gcm_siv_cipher` (the update too) on `inl` octets: AAD without output, else
    /// the message; a NULL input is `final`.
    pub fn cipher(
        &mut self,
        input: Option<&[u8]>,
        inl: usize,
        out: bool,
        outsize: usize,
    ) -> Result<Output, Error> {
        crate::dit::with(|| self.cipher_dit(input, inl, out, outsize))
    }

    /// [`Self::cipher`]'s work.
    fn cipher_dit(
        &mut self,
        input: Option<&[u8]>,
        inl: usize,
        out: bool,
        outsize: usize,
    ) -> Result<Output, Error> {
        if outsize < inl {
            return Err(Error::OutputBufferTooSmall);
        }
        let Some(input) = input else {
            return if self.finish() {
                Ok(Output::new(Vec::new(), inl))
            } else {
                Err(Error::Silent)
            };
        };
        let input = input.get(..inl).ok_or(Error::Silent)?;
        if !out {
            self.aad(input)?;
            return Ok(Output::new(Vec::new(), inl));
        }
        let data = if self.enc {
            self.encrypt(input)?
        } else {
            self.decrypt(input)?
        };
        Ok(Output::new(data, inl))
    }

    /// `aes_gcm_siv_finish`: encrypting, the tag (of an empty message if none was
    /// encrypted); decrypting, whether the computed tag is the one set.
    fn finish(&mut self) -> bool {
        if self.enc {
            if !self.generated_tag && self.encrypt(&[]).is_err() {
                return false;
            }
            return self.generated_tag;
        }
        if !self.generated_tag && self.decrypt(&[]).is_err() {
            return false;
        }
        ct_eq(&self.tag, &self.user_tag) && self.have_user_tag
    }

    /// `final`.
    pub fn finalize(&mut self) -> Result<Output, Error> {
        crate::dit::with(|| self.finalize_dit())
    }

    /// [`Self::finalize`]'s work.
    fn finalize_dit(&mut self) -> Result<Output, Error> {
        if self.finish() {
            Ok(Output::new(Vec::new(), 0))
        } else {
            Err(Error::Silent)
        }
    }

    /// The tag, encrypting once one is generated (`tag` of exactly 16 octets).
    pub fn tag(&self, size: usize) -> Result<[u8; BLOCK], Error> {
        if !self.enc || !self.generated_tag || size != BLOCK {
            return Err(Error::FailedToSetParameter);
        }
        Ok(self.tag)
    }

    /// The `tag` parameter: exactly 16 octets; kept only when decrypting.
    pub fn set_tag(&mut self, tag: &[u8]) -> Result<(), Error> {
        let t: [u8; BLOCK] = tag.try_into().map_err(|_| Error::FailedToGetParameter)?;
        if !self.enc {
            self.user_tag = t;
            self.have_user_tag = true;
        }
        Ok(())
    }

    /// `speed`: any non-zero value allows any number of messages per key.
    pub fn set_speed(&mut self, speed: u32) {
        self.speed = speed != 0;
    }
}
