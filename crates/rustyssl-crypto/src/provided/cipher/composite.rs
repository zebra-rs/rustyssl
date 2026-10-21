//! The AES-CBC-HMAC-SHA1 and -SHA256 composites (`cipher_aes_cbc_hmac_sha.c` and its two
//! `_hw.c`): AES-CBC on whole blocks, or, after a TLS AAD, a TLS record's MAC-then-encrypt and
//! its decryption with the MAC and padding checked in constant time (the reference's
//! Lucky-13 code, ported over SHA's compression function). OpenSSL offers them only on x86-64
//! with AES-NI, so the provider does too.
//!
//! Multi-block encryption (`tls1multi_enc`) writes more than the output size its parameter
//! declares, so it can't be checked and fails here; its sizes are reported as the
//! reference's are (docs/DEVIATIONS.md).

use sha1::block_api::compress as sha1_compress;
use sha2::block_api::compress256;
use zeroize::{Zeroize, Zeroizing};

use super::{Error, Generic, Kind, Mode, Output, add, cbc, sub};

/// `EVP_AEAD_TLS1_AAD_LEN`.
pub const TLS1_AAD_LEN: usize = 13;
/// `TLS1_1_VERSION`.
const TLS1_1_VERSION: u16 = 0x0302;
/// `SSL3_VERSION` and `TLS1_VERSION`: no explicit IV.
const SSL3_VERSION: u32 = 0x0300;
const TLS1_VERSION: u32 = 0x0301;
/// `SSL3_RT_MAX_PLAIN_LENGTH`.
const MAX_PLAIN: usize = 16384;
/// SHA's block.
const CBLOCK: usize = 64;
/// AES's block.
const AES_BLOCK: usize = 16;

const SHA1_H0: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];
const SHA256_H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// A SHA-1 or SHA-256 state with its partial block (`SHA_CTX`, `SHA256_CTX`).
#[derive(Clone)]
struct Sha {
    sha256: bool,
    h: [u32; 8],
    data: [u8; CBLOCK],
    num: usize,
    /// The bits hashed, modulo 2^64.
    bits: u64,
}

impl Drop for Sha {
    fn drop(&mut self) {
        self.h.zeroize();
        self.data.zeroize();
    }
}

impl Sha {
    fn new(sha256: bool) -> Self {
        let mut h = [0u32; 8];
        if sha256 {
            h = SHA256_H0;
        } else if let Some(d) = h.get_mut(..5) {
            d.copy_from_slice(&SHA1_H0);
        }
        Self {
            sha256,
            h,
            data: [0; CBLOCK],
            num: 0,
            bits: 0,
        }
    }

    fn digest_len(&self) -> usize {
        if self.sha256 { 32 } else { 20 }
    }

    /// The compression function on one block.
    fn block(&mut self, b: &[u8; CBLOCK]) {
        if self.sha256 {
            compress256(&mut self.h, core::slice::from_ref(b));
        } else {
            let mut s = [0u32; 5];
            s.iter_mut().zip(self.h.iter()).for_each(|(d, x)| *d = *x);
            sha1_compress(&mut s, core::slice::from_ref(b));
            self.h.iter_mut().zip(s.iter()).for_each(|(d, x)| *d = *x);
            s.zeroize();
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        let n = u64::try_from(data.len()).unwrap_or(0);
        self.bits = self.bits.wrapping_add(n.wrapping_mul(8));
        while !data.is_empty() {
            let take = CBLOCK.saturating_sub(self.num).min(data.len());
            let (head, rest) = data.split_at(take);
            if let Some(d) = self.data.get_mut(self.num..self.num.saturating_add(take)) {
                d.copy_from_slice(head);
            }
            self.num = self.num.saturating_add(take);
            data = rest;
            if self.num == CBLOCK {
                let b = self.data;
                self.block(&b);
                self.num = 0;
            }
        }
    }

    /// The state words as the digest's octets (big-endian).
    fn state_bytes(&self) -> Vec<u8> {
        let words = self.digest_len() / 4;
        self.h
            .iter()
            .take(words)
            .flat_map(|w| w.to_be_bytes())
            .collect()
    }

    /// `SHA*_Final` on a copy.
    fn finish(&self) -> Zeroizing<Vec<u8>> {
        let mut s = self.clone();
        let bits = s.bits;
        s.update(&[0x80]);
        while s.num != CBLOCK - 8 {
            s.update(&[0]);
        }
        s.update(&bits.to_be_bytes());
        Zeroizing::new(s.state_bytes())
    }
}

/// The composite's state beside the generic context's (`PROV_AES_HMAC_SHA*_CTX`).
#[derive(Clone)]
pub(super) struct Hmac {
    head: Sha,
    tail: Sha,
    md: Sha,
    /// The TLS record's payload length once a TLS AAD is set (`payload_length`).
    payload_length: Option<usize>,
    tls_ver: u16,
    tls_aad: [u8; TLS1_AAD_LEN],
    tls_aad_pad: usize,
    /// The `tls-version` parameter (`tlsversion`): once set, decryption's `update` leaves
    /// out the padding and `remove_tls_fixed`.
    tls_version: u32,
    /// The MAC and explicit IV a TLS record's decryption leaves out (`removetlsfixed`), set
    /// with the key; less the IV for SSL 3.0 and TLS 1.0.
    remove_tls_fixed: usize,
    mb_max_send_fragment: usize,
    mb_interleave: u32,
    mb_aad_packlen: u32,
    mb_encrypt_len: usize,
}

impl Hmac {
    pub(super) fn new(sha256: bool) -> Self {
        Self {
            head: Sha::new(sha256),
            tail: Sha::new(sha256),
            md: Sha::new(sha256),
            payload_length: None,
            tls_ver: 0,
            tls_aad: [0; TLS1_AAD_LEN],
            tls_aad_pad: 0,
            tls_version: 0,
            remove_tls_fixed: 0,
            mb_max_send_fragment: 0,
            mb_interleave: 0,
            mb_aad_packlen: 0,
            mb_encrypt_len: 0,
        }
    }

    fn digest_len(&self) -> usize {
        self.head.digest_len()
    }
}

/// The multi-block parameters a caller gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Multiblock {
    /// `tls1multi_interleave`.
    pub interleave: u32,
    /// `tls1multi_aadpacklen`.
    pub aad_packlen: u32,
    /// `tls1multi_enclen`.
    pub encrypt_len: usize,
}

/// `constant_time_ge`-style masks on `usize`: all ones when `a >= b`.
fn ct_ge(a: usize, b: usize) -> usize {
    // The top bit of a - b when it doesn't borrow, computed without a branch.
    let borrow = (a ^ ((a ^ b) | (a.wrapping_sub(b) ^ b))) >> (usize::BITS - 1);
    borrow.wrapping_sub(1)
}

/// All ones when `x` (as a signed number) is negative.
fn ct_neg(x: usize) -> usize {
    0usize.wrapping_sub(x >> (usize::BITS - 1))
}

impl Generic {
    fn hmac(&self) -> Result<&Hmac, Error> {
        self.hmac.as_deref().ok_or(Error::Internal)
    }

    fn hmac_mut(&mut self) -> Result<&mut Hmac, Error> {
        self.hmac.as_deref_mut().ok_or(Error::Internal)
    }

    /// Whether the mode is a composite.
    pub(super) fn is_composite(&self) -> bool {
        matches!(
            self.kind,
            Kind::Block {
                mode: Mode::CbcHmacSha1 | Mode::CbcHmacSha256,
                ..
            }
        )
    }

    /// The key schedule's side effect: the MAC key and any TLS AAD are forgotten.
    pub(super) fn composite_key(&mut self) {
        let sha256 = self.kind.composite_sha256();
        if let Some(h) = self.hmac.as_deref_mut() {
            h.head = Sha::new(sha256);
            h.tail = h.head.clone();
            h.md = h.head.clone();
            h.payload_length = None;
            h.remove_tls_fixed = h.digest_len().saturating_add(AES_BLOCK);
        }
    }

    /// The `tls-version` parameter (`aes_set_ctx_params`): SSL 3.0 and TLS 1.0 records have
    /// no explicit IV, so each such setting takes a block off what decryption leaves out (and
    /// fails, as the reference's assertion does, once less than a block is left).
    pub fn set_composite_tls_version(&mut self, version: u32) -> Result<(), Error> {
        let h = self.hmac_mut()?;
        h.tls_version = version;
        if version == SSL3_VERSION || version == TLS1_VERSION {
            h.remove_tls_fixed = h
                .remove_tls_fixed
                .checked_sub(AES_BLOCK)
                .ok_or(Error::Internal)?;
        }
        Ok(())
    }

    /// `ossl_cipher_generic_stream_update`'s TLS step after a decryption: with a TLS version
    /// set, the output's length leaves out the padding (its last octet, plus one) and then
    /// the MAC and explicit IV. A record too short for either fails without an error.
    pub(super) fn composite_tls_unpad(&self, out: &mut Output) -> Result<(), Error> {
        let h = self.hmac()?;
        if self.enc || h.tls_version == 0 || out.failed.is_some() {
            return Ok(());
        }
        let pad = usize::from(out.data.last().copied().unwrap_or(0));
        out.len = out
            .len
            .checked_sub(pad.saturating_add(1))
            .and_then(|n| n.checked_sub(h.remove_tls_fixed))
            .ok_or(Error::Silent)?;
        Ok(())
    }

    /// The `mackey` parameter (`*_set_mac_key`): HMAC's inner and outer starts.
    pub fn set_mac_key(&mut self, key: &[u8]) -> Result<(), Error> {
        let h = self.hmac_mut()?;
        let sha256 = h.head.sha256;
        let mut k = Zeroizing::new([0u8; CBLOCK]);
        if key.len() > CBLOCK {
            let mut s = Sha::new(sha256);
            s.update(key);
            let d = s.finish();
            k.iter_mut().zip(d.iter()).for_each(|(a, b)| *a = *b);
        } else {
            k.iter_mut().zip(key).for_each(|(a, b)| *a = *b);
        }
        k.iter_mut().for_each(|b| *b ^= 0x36);
        h.head = Sha::new(sha256);
        h.head.update(k.as_slice());
        k.iter_mut().for_each(|b| *b ^= 0x36 ^ 0x5c);
        h.tail = Sha::new(sha256);
        h.tail.update(k.as_slice());
        Ok(())
    }

    /// The `tlsaad` parameter (`*_set_tls1_aad`). Encrypting with TLS 1.1 or later, the
    /// record length in `aad` loses the explicit IV, written back to the caller's AAD as the
    /// reference does. `Err` for a failure, which raises nothing.
    pub fn set_composite_tls_aad(&mut self, aad: &mut [u8]) -> Result<(), Error> {
        let enc = self.enc;
        let h = self.hmac_mut()?;
        if aad.len() != TLS1_AAD_LEN {
            return Err(Error::Silent);
        }
        let dlen = h.digest_len();
        let at = |i: usize| aad.get(i).copied().unwrap_or(0);
        let mut len = usize::from(at(11)) << 8 | usize::from(at(12));
        if !enc {
            h.tls_aad.copy_from_slice(aad);
            h.payload_length = Some(TLS1_AAD_LEN);
            h.tls_aad_pad = dlen;
            return Ok(());
        }
        h.payload_length = Some(len);
        h.tls_ver = u16::from(at(9)) << 8 | u16::from(at(10));
        if h.tls_ver >= TLS1_1_VERSION {
            len = len.checked_sub(AES_BLOCK).ok_or(Error::Silent)?;
            let n = u16::try_from(len).unwrap_or(0).to_be_bytes();
            if let Some(d) = aad.get_mut(11..13) {
                d.copy_from_slice(&n);
            }
        }
        h.md = h.head.clone();
        h.md.update(aad);
        let total = add(add(len, dlen)?, AES_BLOCK)? & !(AES_BLOCK - 1);
        h.tls_aad_pad = sub(total, len)?;
        Ok(())
    }

    /// `tlsaadpad`.
    pub fn composite_tls_aad_pad(&self) -> usize {
        self.hmac().map_or(0, |h| h.tls_aad_pad)
    }

    /// The composite's operation (`*_cipher`) on `len` octets: CBC on whole blocks, or a TLS
    /// record after a TLS AAD.
    pub(super) fn composite_cipher(&mut self, input: &[u8]) -> Result<Output, Error> {
        let plen = self.hmac_mut()?.payload_length.take();
        let len = input.len();
        if !len.is_multiple_of(AES_BLOCK) {
            return Err(Error::CipherOperationFailed);
        }
        if self.enc {
            self.composite_encrypt(input, plen)
        } else {
            self.composite_decrypt(input, plen)
        }
    }

    /// AES-CBC in place from the running IV in the context's direction.
    fn aes_cbc(&mut self, data: &mut [u8]) -> Result<(), Error> {
        if data.is_empty() {
            return Ok(());
        }
        let cipher = self.cipher.as_ref().ok_or(Error::NoKeySet)?;
        let iv = self.iv.get_mut(..AES_BLOCK).ok_or(Error::Internal)?;
        cbc(cipher.as_ref(), iv, data, self.enc).map_err(|_| Error::CipherOperationFailed)
    }

    fn composite_encrypt(&mut self, input: &[u8], plen: Option<usize>) -> Result<Output, Error> {
        let len = input.len();
        let mut out = Zeroizing::new(input.to_vec());
        let Some(plen) = plen else {
            self.aes_cbc(&mut out)?;
            return Ok(Output::new(out.to_vec(), len));
        };
        let h = self.hmac_mut()?;
        let dlen = h.digest_len();
        if len != add(add(plen, dlen)?, AES_BLOCK)? & !(AES_BLOCK - 1) {
            return Err(Error::CipherOperationFailed);
        }
        let iv = if h.tls_ver >= TLS1_1_VERSION {
            AES_BLOCK
        } else {
            0
        };
        h.md.update(input.get(iv..plen).ok_or(Error::CipherOperationFailed)?);
        let inner = h.md.finish();
        h.md = h.tail.clone();
        h.md.update(&inner);
        let mac = h.md.finish();
        let end = add(plen, dlen)?;
        out.get_mut(plen..end)
            .ok_or(Error::Internal)?
            .copy_from_slice(&mac);
        let pad = u8::try_from(sub(sub(len, end)?, 1)?).map_err(|_| Error::Internal)?;
        out.get_mut(end..).ok_or(Error::Internal)?.fill(pad);
        self.aes_cbc(&mut out)?;
        Ok(Output::new(out.to_vec(), len))
    }

    fn composite_decrypt(&mut self, input: &[u8], plen: Option<usize>) -> Result<Output, Error> {
        let sha256 = self.kind.composite_sha256();
        let mut out = Zeroizing::new(input.to_vec());
        let Some(plen) = plen else {
            self.aes_cbc(&mut out)?;
            let len = out.len();
            return Ok(Output::new(out.to_vec(), len));
        };
        let h = self.hmac()?;
        let dlen = h.digest_len();
        let aad = h.tls_aad;
        let ver = u16::from(aad.get(plen.wrapping_sub(4)).copied().unwrap_or(0)) << 8
            | u16::from(aad.get(plen.wrapping_sub(3)).copied().unwrap_or(0));
        let iv = if ver >= TLS1_1_VERSION { AES_BLOCK } else { 0 };
        // SHA-256's decrypts the whole record (explicit IV block included) before its checks;
        // SHA-1's takes the explicit IV as the IV and leaves its block of the output alone.
        let mut at = 0;
        let mut head = Zeroizing::new(Vec::new());
        if sha256 {
            self.aes_cbc(&mut out)?;
            if input.len() < add(iv, add(dlen, 1)?)? {
                let mut o = Output::new(out.to_vec(), 0);
                o.failed = Some(Error::CipherOperationFailed);
                return Ok(o);
            }
            // The explicit IV's block is written too, decrypted under the context's IV.
            head.extend(out.drain(..iv));
        } else {
            if input.len() < add(iv, add(dlen, 1)?)? {
                return Err(Error::CipherOperationFailed);
            }
            if iv > 0 {
                self.iv
                    .get_mut(..AES_BLOCK)
                    .ok_or(Error::Internal)?
                    .copy_from_slice(input.get(..AES_BLOCK).ok_or(Error::Internal)?);
                out.drain(..iv);
                at = iv;
            }
            self.aes_cbc(&mut out)?;
        }
        let ok = self.check_record(&mut out, aad, dlen)?;
        head.extend_from_slice(&out);
        let mut o = Output::new(head.to_vec(), input.len());
        o.at = at;
        if !ok {
            o.failed = Some(Error::CipherOperationFailed);
        }
        Ok(o)
    }

    /// The MAC and padding of a decrypted record (`out`: payload, MAC, padding), checked in
    /// constant time as the reference does: the HMAC over the AAD and the payload is computed
    /// for every padding length the record could have, its state captured where the real one
    /// ends. Updates the AAD's length as the payload's.
    fn check_record(
        &mut self,
        out: &mut [u8],
        mut aad: [u8; TLS1_AAD_LEN],
        dlen: usize,
    ) -> Result<bool, Error> {
        let full = out.len();
        let mut len = full;
        let pad_byte = out.last().copied().unwrap_or(0);
        let mut pad = usize::from(pad_byte);
        let mut maxpad = sub(len, add(dlen, 1)?)?;
        // min(maxpad, 255) without a branch on the (public) length.
        maxpad |= ct_neg(255usize.wrapping_sub(maxpad)) & 0xff;
        maxpad &= 255;
        let good = ct_ge(maxpad, pad);
        pad = (pad & good) | (maxpad & !good);
        let mut ret = good;
        let mut inp_len = len.wrapping_sub(dlen.wrapping_add(pad).wrapping_add(1));
        if let Some(d) = aad.get_mut(11..13) {
            d.copy_from_slice(&u16::try_from(inp_len & 0xffff).unwrap_or(0).to_be_bytes());
        }
        let h = self.hmac_mut()?;
        h.tls_aad = aad;
        let mut md = h.head.clone();
        md.update(&aad);
        len = sub(len, dlen)?;
        let mut base = 0usize;
        if len >= 256 + CBLOCK {
            let j = sub(
                add(sub(len, 256 + CBLOCK)? & !(CBLOCK - 1), CBLOCK)?,
                md.num,
            )?;
            md.update(out.get(..j).ok_or(Error::Internal)?);
            base = j;
            len = sub(len, j)?;
            inp_len = inp_len.wrapping_sub(j);
        }
        // The bit length of the inner hash's message, at most 18 bits beyond what's hashed.
        let bitlen = u32::try_from(md.bits & 0xffff_ffff)
            .unwrap_or(0)
            .wrapping_add(u32::try_from(inp_len & 0x00ff_ffff).unwrap_or(0) << 3);
        let words = dlen / 4;
        let mut pmac = [0u32; 8];
        let mut data = Zeroizing::new(md.data);
        let mut res = md.num;
        let mut j = 0usize;
        let capture = |pmac: &mut [u32; 8], md: &Sha, mask: usize| {
            let m = u32::try_from(mask & 0xffff_ffff).unwrap_or(0);
            for (p, x) in pmac.iter_mut().zip(md.h.iter()).take(words) {
                *p |= x & m;
            }
        };
        let set_len = |data: &mut [u8; CBLOCK], mask: usize| {
            let m = u32::try_from(mask & 0xffff_ffff).unwrap_or(0);
            if let Some(w) = data.get_mut(CBLOCK - 4..) {
                let mut word = [0u8; 4];
                word.copy_from_slice(w);
                let old = u32::from_be_bytes(word);
                w.copy_from_slice(&(old | (bitlen & m)).to_be_bytes());
            }
        };
        while j < len {
            let mut c = usize::from(out.get(base.wrapping_add(j)).copied().unwrap_or(0));
            let mask = ct_neg(j.wrapping_sub(inp_len));
            c &= mask;
            c |= 0x80 & !mask & !ct_neg(inp_len.wrapping_sub(j));
            if let Some(d) = data.get_mut(res) {
                *d = u8::try_from(c & 0xff).unwrap_or(0);
            }
            res = res.wrapping_add(1);
            if res == CBLOCK {
                let mut mask = ct_neg(inp_len.wrapping_add(7).wrapping_sub(j));
                set_len(&mut data, mask);
                md.block(&data);
                mask &= ct_neg(j.wrapping_sub(inp_len).wrapping_sub(72));
                capture(&mut pmac, &md, mask);
                res = 0;
            }
            j = j.wrapping_add(1);
        }
        for i in res..CBLOCK {
            if let Some(d) = data.get_mut(i) {
                *d = 0;
            }
            j = j.wrapping_add(1);
        }
        if res > CBLOCK - 8 {
            let mut mask = ct_neg(inp_len.wrapping_add(8).wrapping_sub(j));
            set_len(&mut data, mask);
            md.block(&data);
            mask &= ct_neg(j.wrapping_sub(inp_len).wrapping_sub(73));
            capture(&mut pmac, &md, mask);
            data.fill(0);
            j = j.wrapping_add(64);
        }
        if let Some(w) = data.get_mut(CBLOCK - 4..) {
            w.copy_from_slice(&bitlen.to_be_bytes());
        }
        md.block(&data);
        let mask = ct_neg(j.wrapping_sub(inp_len).wrapping_sub(73));
        capture(&mut pmac, &md, mask);
        let mut inner = Zeroizing::new([0u8; 32]);
        for (chunk, w) in inner.chunks_mut(4).zip(pmac.iter()).take(words) {
            chunk.copy_from_slice(&w.to_be_bytes());
        }
        pmac.zeroize();
        let h = self.hmac()?;
        let mut outer = h.tail.clone();
        outer.update(inner.get(..dlen).ok_or(Error::Internal)?);
        let mac = outer.finish();
        // The MAC and padding: the last maxpad + dlen octets before the padding length,
        // examined whatever the padding is.
        let region = add(maxpad, dlen)?;
        let start = sub(sub(full, 1)?, region)?;
        let off = sub(maxpad, pad)?;
        let mut diff = 0usize;
        let mut i = 0usize;
        for k in 0..region {
            let c = usize::from(out.get(start.wrapping_add(k)).copied().unwrap_or(0));
            let mut cmask = ct_neg(k.wrapping_sub(off).wrapping_sub(dlen));
            diff |= (c ^ pad) & !cmask;
            cmask &= ct_neg(off.wrapping_sub(1).wrapping_sub(k));
            diff |= (c ^ usize::from(mac.get(i).copied().unwrap_or(0))) & cmask;
            i = i.wrapping_add(1 & cmask);
        }
        ret &= !ct_neg(0usize.wrapping_sub(diff));
        Ok(ret != 0)
    }

    /// The multi-block parameters: the interleave, the AAD's packet length, the last
    /// encryption's length.
    pub fn multiblock(&self) -> Multiblock {
        self.hmac().map_or(
            Multiblock {
                interleave: 0,
                aad_packlen: 0,
                encrypt_len: 0,
            },
            |h| Multiblock {
                interleave: h.mb_interleave,
                aad_packlen: h.mb_aad_packlen,
                encrypt_len: h.mb_encrypt_len,
            },
        )
    }

    /// `tls1multi_maxsndfrag`.
    pub fn set_max_send_fragment(&mut self, n: usize) -> Result<(), Error> {
        self.hmac_mut()?.mb_max_send_fragment = n;
        Ok(())
    }

    /// `tls1multi_maxbufsz`: one record's room. The reference asserts (and aborts) when no
    /// fragment size was set; here it fails (docs/DEVIATIONS.md).
    pub fn multiblock_max_bufsize(&self) -> Result<usize, Error> {
        let h = self.hmac()?;
        if h.mb_max_send_fragment == 0 {
            return Err(Error::FailedToSetParameter);
        }
        let dlen = h.digest_len();
        let room = h
            .mb_max_send_fragment
            .checked_add(dlen.wrapping_add(AES_BLOCK))
            .ok_or(Error::FailedToSetParameter)?
            & !(AES_BLOCK - 1);
        // The reference computes it as an `int`.
        let n = room
            .checked_add(5 + AES_BLOCK)
            .ok_or(Error::FailedToSetParameter)?;
        let n = i32::try_from(n & 0xffff_ffff)
            .or_else(|_| {
                i32::try_from(n & 0x7fff_ffff).map(|v| v.wrapping_sub(i32::MAX).wrapping_sub(1))
            })
            .unwrap_or(0);
        usize::try_from(n).map_err(|_| Error::FailedToSetParameter)
    }

    /// `tls1multi_aad` with `tls1multi_interleave` (`*_tls1_multiblock_aad`): the interleave
    /// and the packets' length for a record header `aad`. `avx2` is whether the CPU has AVX2,
    /// which the reference interleaves 8 records on for 8 KiB and more.
    pub fn set_multiblock_aad(
        &mut self,
        aad: &[u8],
        interleave: u32,
        avx2: bool,
    ) -> Result<(), Error> {
        let enc = self.enc;
        let h = self.hmac_mut()?;
        let at = |i: usize| aad.get(i).copied().unwrap_or(0);
        if aad.len() < TLS1_AAD_LEN || !matches!(interleave, 4 | 8) {
            return Err(Error::FailedToGetParameter);
        }
        let mut inp_len = usize::from(at(11)) << 8 | usize::from(at(12));
        if inp_len > MAX_PLAIN || aad.len() > MAX_PLAIN.saturating_mul(interleave as usize) {
            return Err(Error::FailedToGetParameter);
        }
        h.mb_interleave = interleave;
        if !enc {
            return Err(Error::Silent);
        }
        if (u16::from(at(9)) << 8 | u16::from(at(10))) < TLS1_1_VERSION {
            return Err(Error::Silent);
        }
        let mut n4x = 1u32;
        if inp_len != 0 {
            if inp_len < 4096 {
                return Err(Error::Silent);
            }
            if inp_len >= 8192 && avx2 {
                n4x = 2;
            }
        } else {
            n4x = interleave / 4;
            if n4x == 0 || n4x > 2 {
                return Err(Error::Silent);
            }
            inp_len = aad.len();
        }
        h.md = h.head.clone();
        h.md.update(aad.get(..TLS1_AAD_LEN).unwrap_or_default());
        let dlen = h.digest_len();
        let x4 = 4 * n4x as usize;
        let shift = n4x.wrapping_add(1);
        let mut frag = inp_len >> shift;
        let mut last = inp_len.wrapping_add(frag).wrapping_sub(frag << shift);
        if last > frag && last.wrapping_add(13 + 9) % 64 < x4.wrapping_sub(1) {
            frag = frag.wrapping_add(1);
            last = last.wrapping_sub(x4.wrapping_sub(1));
        }
        let record = |n: usize| (n.wrapping_add(dlen).wrapping_add(16) & !15).wrapping_add(5 + 16);
        let mut packlen = record(frag);
        packlen = (packlen << shift).wrapping_sub(packlen);
        packlen = packlen.wrapping_add(record(last));
        h.mb_interleave = u32::try_from(x4).unwrap_or(0);
        h.mb_aad_packlen = u32::try_from(packlen & 0xffff_ffff).unwrap_or(0);
        Ok(())
    }
}
