//! The default provider's AEAD ciphers with the semantics of their provider functions: GCM
//! (`ciphercommon_gcm.c` over a port of `crypto/modes/gcm128.c`), CCM (`ciphercommon_ccm.c`,
//! `ccm128.c`), OCB (`cipher_aes_ocb.c`, `ocb128.c`), and ChaCha20-Poly1305
//! (`cipher_chacha20_poly1305*.c`), including their TLS record modes.
//!
//! The modes are ported rather than taken from the AEAD crates because OpenSSL's API feeds
//! them AAD and data in pieces and its observable state follows its own state machines: GCM's
//! AAD after data fails, a zero-length update ends the AAD; CCM takes the tag and nonce lengths
//! when the key is set, needs the message length before AAD, and checks the tag with the last
//! update; OCB buffers whole blocks and finishes the partial ones in `final`; ChaCha20-Poly1305
//! restarts its key stream after each tag. The block ciphers, GHASH, and Poly1305 are the
//! vetted crates' (`sym`). Tags are compared in constant time, and a decryption that doesn't
//! authenticate wipes the output it wrote, as OpenSSL does.
//!
//! Random IVs (GCM's when none is set, and the TLS fixed IV's random part) come from the
//! operating system until the library's generators (3.7).
//!
//! Deviations (docs/DEVIATIONS.md): GCM's TLS fixed IV and inverted IV longer than the IV, and
//! CCM's IV requested into more room than the IV, would write or read outside the context in
//! the reference; here they fail, and copy only the IV (zero-filled), respectively.

use zeroize::{Zeroize, Zeroizing};

use super::cipher::{ChaCha, Error, Output};
use crate::sym::{self, BlockAlgorithm, BlockCipher, HashAlgorithm, UniversalHash};

/// `EVP_AEAD_TLS1_AAD_LEN`.
const TLS1_AAD_LEN: usize = 13;
/// `EVP_GCM_TLS_FIXED_IV_LEN` (CCM's too).
const TLS_FIXED_IV_LEN: usize = 4;
/// `EVP_GCM_TLS_EXPLICIT_IV_LEN` (CCM's too).
const TLS_EXPLICIT_IV_LEN: usize = 8;
/// `EVP_GCM_TLS_TAG_LEN`, `POLY1305_BLOCK_SIZE`.
const TAG_LEN: usize = 16;
/// `GCM_IV_MAX_SIZE`.
const GCM_IV_MAX: usize = 128;
/// `GCM_IV_DEFAULT_SIZE`.
const GCM_IV_DEFAULT: usize = 12;

/// The direction and buffers of one provider call.
#[derive(Debug, Clone, Copy)]
pub struct Io<'a> {
    /// The input, `None` for a NULL pointer (with `inl` as given).
    pub input: Option<&'a [u8]>,
    /// The length given.
    pub inl: usize,
    /// Whether the output pointer is non-NULL (AAD has none).
    pub out: bool,
    /// Whether the output is the input (the TLS modes work in place).
    pub in_place: bool,
    /// The room at the output.
    pub outsize: usize,
}

/// A keyed block cipher that copies.
struct Key(Box<dyn BlockCipher>);

impl Clone for Key {
    fn clone(&self) -> Self {
        Self(self.0.clone_box())
    }
}

impl Key {
    fn new(algorithm: BlockAlgorithm, key: &[u8]) -> Result<Self, Error> {
        sym::block_cipher(algorithm, key, None)
            .map(Self)
            .map_err(|_| Error::CipherOperationFailed)
    }

    /// One block, encrypted in place.
    fn encrypt(&self, block: &mut [u8; 16]) -> Result<(), Error> {
        self.0
            .encrypt_blocks(block)
            .map_err(|_| Error::CipherOperationFailed)
    }

    /// One block, decrypted in place.
    fn decrypt(&self, block: &mut [u8; 16]) -> Result<(), Error> {
        self.0
            .decrypt_blocks(block)
            .map_err(|_| Error::CipherOperationFailed)
    }
}

/// A universal hash that copies.
struct Hash(Box<dyn UniversalHash>);

impl Clone for Hash {
    fn clone(&self) -> Self {
        Self(self.0.clone_box())
    }
}

fn xor16(a: &mut [u8; 16], b: &[u8; 16]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= y;
    }
}

/// Octet `i` of `a` (0 past its end).
fn at(a: &[u8], i: usize) -> u8 {
    a.get(i).copied().unwrap_or(0)
}

/// Sets octet `i` of `a` (nothing past its end).
fn put(a: &mut [u8], i: usize, v: u8) {
    if let Some(x) = a.get_mut(i) {
        *x = v;
    }
}

/// Constant-time equality of two octet strings of one length.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

/// `IV_STATE_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IvState {
    /// No IV yet.
    Uninitialised,
    /// An IV is in the buffer, not yet in the mode.
    Buffered,
    /// The mode has the IV.
    Copied,
    /// The IV has been used up.
    Finished,
}

// -------------------------------------------------------------------------------------------
// GCM

/// The key as the low-level code's block function.
struct KeyBlock<'a>(&'a Key);

impl crate::lowlevel::modes::Block128 for KeyBlock<'_> {
    fn block(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut b = *input;
        // AES and the other 128-bit block ciphers don't fail on a block.
        let _ = self.0.encrypt(&mut b);
        b
    }
}

/// The key as the low-level code's CTR function (`ctr128_f`, as AES-NI's and ARMv8's
/// `ctr32_encrypt_blocks`): the counter blocks of a run encrypted many at a time.
struct KeyCtr<'a>(&'a Key);

impl crate::lowlevel::modes::Ctr128 for KeyCtr<'_> {
    fn ctr(&self, input: &[u8], out: &mut [u8], blocks: usize, iv: &[u8; 16]) {
        let len = blocks.saturating_mul(16).min(input.len()).min(out.len());
        if let (Some(i), Some(o)) = (input.get(..len), out.get_mut(..len)) {
            o.copy_from_slice(i);
            self.ctr_in_place(o, blocks, iv);
        }
    }

    fn ctr_in_place(&self, data: &mut [u8], blocks: usize, iv: &[u8; 16]) {
        const BATCH: usize = 32;
        let mut stream = Zeroizing::new([0u8; BATCH * 16]);
        let (head, tail) = iv.split_at(12);
        let mut counter = u32::from_be_bytes(tail.try_into().unwrap_or([0; 4]));
        let len = blocks.saturating_mul(16).min(data.len());
        for chunk in data.get_mut(..len).unwrap_or_default().chunks_mut(BATCH * 16) {
            let Some(buf) = stream.get_mut(..chunk.len()) else {
                return;
            };
            for slot in buf.as_chunks_mut::<16>().0 {
                let (fixed, count) = slot.split_at_mut(12);
                fixed.copy_from_slice(head);
                count.copy_from_slice(&counter.to_be_bytes());
                counter = counter.wrapping_add(1);
            }
            // AES and the other 128-bit block ciphers don't fail on whole blocks.
            let _ = self.0.0.encrypt_blocks(buf);
            for (d, k) in chunk.iter_mut().zip(buf.iter()) {
                *d ^= k;
            }
        }
    }
}

/// `GCM128_CONTEXT` without the key: `CRYPTO_gcm128_*` as `lowlevel::aead` ports them, with
/// OpenSSL's GHASH buffering (`Xn`), so a context used after a failed check, or finished twice,
/// hashes on exactly as the reference's does.
#[derive(Clone)]
struct Gcm128(crate::lowlevel::aead::Gcm);

impl Gcm128 {
    /// `CRYPTO_gcm128_init`.
    fn new(key: &Key) -> Result<Self, Error> {
        Ok(Self(crate::lowlevel::aead::Gcm::new(&KeyBlock(key))))
    }

    /// `CRYPTO_gcm128_setiv`.
    fn setiv(&mut self, key: &Key, iv: &[u8]) -> Result<(), Error> {
        self.0.setiv(iv, &KeyBlock(key));
        Ok(())
    }

    /// `CRYPTO_gcm128_aad`: -2 after data, -1 past the limit.
    fn aad(&mut self, aad: &[u8]) -> Result<(), i32> {
        match self.0.aad(aad) {
            0 => Ok(()),
            r => Err(r),
        }
    }

    /// `CRYPTO_gcm128_encrypt`/`_decrypt` in place: -1 past the limit.
    fn crypt(&mut self, key: &Key, data: &mut [u8], enc: bool) -> Result<(), i32> {
        let r = self
            .0
            .crypt_in_place(data, &KeyBlock(key), Some(&KeyCtr(key)), enc);
        if r == 0 { Ok(()) } else { Err(r) }
    }

    /// `CRYPTO_gcm128_finish`'s tag (`CRYPTO_gcm128_tag`).
    fn tag(&mut self) -> [u8; 16] {
        let mut t = [0u8; 16];
        self.0.tag(&mut t);
        t
    }
}

/// A GCM context (`PROV_GCM_CTX`).
#[derive(Clone)]
pub struct Gcm {
    algorithm: BlockAlgorithm,
    keylen: usize,
    ivlen: usize,
    taglen: Option<usize>,
    tls_aad_pad_sz: usize,
    tls_aad_len: Option<usize>,
    tls_enc_records: u64,
    iv_state: IvState,
    enc: bool,
    key_set: bool,
    iv_gen_rand: bool,
    iv_gen: bool,
    iv: Zeroizing<[u8; GCM_IV_MAX]>,
    /// The tag, or the TLS AAD.
    buf: Zeroizing<[u8; 16]>,
    key: Option<Key>,
    gcm: Option<Gcm128>,
    /// Where random IVs come from (the operating system without one).
    rng: Option<crate::rand::Random>,
}

impl Gcm {
    /// `ossl_gcm_initctx`.
    pub fn new(algorithm: BlockAlgorithm, keylen: usize) -> Self {
        Self {
            algorithm,
            keylen,
            ivlen: TLS_FIXED_IV_LEN + TLS_EXPLICIT_IV_LEN,
            taglen: None,
            tls_aad_pad_sz: 0,
            tls_aad_len: None,
            tls_enc_records: 0,
            iv_state: IvState::Uninitialised,
            enc: false,
            key_set: false,
            iv_gen_rand: false,
            iv_gen: false,
            iv: Zeroizing::new([0; GCM_IV_MAX]),
            buf: Zeroizing::new([0; 16]),
            key: None,
            gcm: None,
            rng: None,
        }
    }

    /// Draws random IVs from `rng` (the library's generators, as the reference's
    /// `RAND_bytes_ex` with the context's library context).
    pub fn set_random(&mut self, rng: crate::rand::Random) {
        self.rng = Some(rng);
    }

    /// `gcm_init` before the parameters.
    pub fn init(&mut self, enc: bool, key: Option<&[u8]>, iv: Option<&[u8]>) -> Result<(), Error> {
        crate::dit::with(|| self.init_dit(enc, key, iv))
    }

    /// [`Self::init`]'s work.
    fn init_dit(&mut self, enc: bool, key: Option<&[u8]>, iv: Option<&[u8]>) -> Result<(), Error> {
        self.enc = enc;
        if let Some(iv) = iv {
            if iv.is_empty() || iv.len() > GCM_IV_MAX {
                return Err(Error::InvalidIvLength);
            }
            self.ivlen = iv.len();
            if let Some(d) = self.iv.get_mut(..iv.len()) {
                d.copy_from_slice(iv);
            }
            self.iv_state = IvState::Buffered;
        }
        if let Some(key) = key {
            if key.len() != self.keylen {
                return Err(Error::InvalidKeyLength);
            }
            let k = Key::new(self.algorithm, key)?;
            self.gcm = Some(Gcm128::new(&k)?);
            self.key = Some(k);
            self.key_set = true;
            self.tls_enc_records = 0;
        }
        Ok(())
    }

    fn iv(&self) -> &[u8] {
        self.iv.get(..self.ivlen).unwrap_or_default()
    }

    /// The mode's `setiv` with the IV buffer.
    fn hw_setiv(&mut self) -> Result<(), Error> {
        let iv = Zeroizing::new(self.iv().to_vec());
        let (Some(k), Some(g)) = (self.key.as_ref(), self.gcm.as_mut()) else {
            return Err(Error::Silent);
        };
        g.setiv(k, &iv)
    }

    /// `gcm_iv_generate`.
    fn iv_generate(&mut self, offset: usize) -> bool {
        if self.ivlen <= offset || self.ivlen < GCM_IV_DEFAULT {
            return false;
        }
        let Some(r) = self.iv.get_mut(offset..self.ivlen) else {
            return false;
        };
        if !crate::rand::fill(self.rng.as_ref(), r) {
            return false;
        }
        self.iv_state = IvState::Buffered;
        self.iv_gen_rand = true;
        true
    }

    /// `getivgen`: the IV's last `olen` octets (all of it for 0 or more), then the invocation
    /// field counts on.
    pub fn iv_gen(&mut self, olen: usize) -> Result<Vec<u8>, Error> {
        if !self.iv_gen || !self.key_set {
            return Err(Error::Silent);
        }
        self.hw_setiv()?;
        let olen = if olen == 0 || olen > self.ivlen {
            self.ivlen
        } else {
            olen
        };
        let out = self
            .iv
            .get(self.ivlen.saturating_sub(olen)..self.ivlen)
            .unwrap_or_default()
            .to_vec();
        // ctr64_inc of the last 8 octets.
        if let Some(c) = self.iv.get_mut(self.ivlen.saturating_sub(8)..self.ivlen) {
            for b in c.iter_mut().rev() {
                *b = b.wrapping_add(1);
                if *b != 0 {
                    break;
                }
            }
        }
        self.iv_state = IvState::Copied;
        Ok(out)
    }

    /// `setivinv`: the IV's last octets from the peer, decrypting only.
    pub fn set_iv_inv(&mut self, inv: &[u8]) -> Result<(), Error> {
        if !self.iv_gen || !self.key_set || self.enc || inv.len() > self.ivlen {
            return Err(Error::Silent);
        }
        let at = self.ivlen.saturating_sub(inv.len());
        if let Some(d) = self.iv.get_mut(at..self.ivlen) {
            d.copy_from_slice(inv);
        }
        self.hw_setiv()?;
        self.iv_state = IvState::Copied;
        Ok(())
    }

    /// The IV length.
    pub fn iv_len(&self) -> usize {
        self.ivlen
    }

    /// The key length.
    pub fn key_len(&self) -> usize {
        self.keylen
    }

    /// The tag length reported (16 until set).
    pub fn tag_len(&self) -> usize {
        self.taglen.unwrap_or(TAG_LEN)
    }

    /// The IV for `iv` and `updated-iv`: `None` before there is one.
    pub fn iv_buffer(&mut self) -> Option<&mut [u8]> {
        if self.iv_state == IvState::Uninitialised {
            return None;
        }
        self.iv.get_mut(..self.ivlen)
    }

    /// The TLS AAD's padding (`tls-aad-pad`).
    pub fn tls_aad_pad(&self) -> usize {
        self.tls_aad_pad_sz
    }

    /// Whether the IV was generated at random (`iv-generated`).
    pub fn iv_generated(&self) -> bool {
        self.iv_gen_rand
    }

    /// The tag's first `sz` octets, encrypting after `final`.
    pub fn tag(&self, sz: usize) -> Result<&[u8], Error> {
        if sz == 0 || sz > TAG_LEN || !self.enc || self.taglen.is_none() {
            return Err(Error::InvalidTag);
        }
        self.buf.get(..sz).ok_or(Error::InvalidTag)
    }

    /// Sets the expected tag (at most 16 octets, decrypting); the buffer takes it first.
    pub fn set_tag(&mut self, tag: &[u8]) -> Result<(), Error> {
        if let Some(d) = self.buf.get_mut(..tag.len()) {
            d.copy_from_slice(tag);
        }
        if tag.is_empty() || self.enc {
            return Err(Error::InvalidTag);
        }
        self.taglen = Some(tag.len());
        Ok(())
    }

    /// Sets the IV length (an IV already set is then used up).
    pub fn set_iv_len(&mut self, sz: usize) -> Result<(), Error> {
        if sz == 0 || sz > GCM_IV_MAX {
            return Err(Error::InvalidIvLength);
        }
        if self.ivlen != sz {
            if self.iv_state != IvState::Uninitialised {
                self.iv_state = IvState::Finished;
            }
            self.ivlen = sz;
        }
        Ok(())
    }

    /// `gcm_tls_init`: the record's AAD, its length less the explicit IV (and tag); the padding,
    /// or `None` (the AAD is kept either way).
    pub fn tls_init(&mut self, aad: &[u8]) -> Option<usize> {
        if aad.len() != TLS1_AAD_LEN {
            return None;
        }
        if let Some(d) = self.buf.get_mut(..TLS1_AAD_LEN) {
            d.copy_from_slice(aad);
        }
        self.tls_aad_len = Some(TLS1_AAD_LEN);
        let (hi, lo) = (self.buf.get(11).copied()?, self.buf.get(12).copied()?);
        let mut len = usize::from(u16::from_be_bytes([hi, lo]));
        len = len.checked_sub(TLS_EXPLICIT_IV_LEN)?;
        if !self.enc {
            len = len.checked_sub(TAG_LEN)?;
        }
        let [h, l] = u16::try_from(len).ok()?.to_be_bytes();
        if let Some(b) = self.buf.get_mut(11) {
            *b = h;
        }
        if let Some(b) = self.buf.get_mut(12) {
            *b = l;
        }
        self.tls_aad_pad_sz = TAG_LEN;
        Some(TAG_LEN)
    }

    /// `gcm_tls_iv_set_fixed`: `None` for the whole IV (a length of `(size_t)-1`).
    pub fn tls_iv_fixed(&mut self, fixed: &[u8], whole: bool) -> Result<(), Error> {
        if whole {
            if fixed.len() < self.ivlen {
                return Err(Error::Silent);
            }
            if let (Some(d), Some(s)) = (self.iv.get_mut(..self.ivlen), fixed.get(..self.ivlen)) {
                d.copy_from_slice(s);
            }
            self.iv_gen_rand = false;
            self.iv_gen = true;
            self.iv_state = IvState::Buffered;
            return Ok(());
        }
        let len = fixed.len();
        // The reference's check wraps for a length past the IV and then writes past it.
        if len < TLS_FIXED_IV_LEN
            || len > self.ivlen
            || self.ivlen.wrapping_sub(len) < TLS_EXPLICIT_IV_LEN
        {
            return Err(Error::Silent);
        }
        if let Some(d) = self.iv.get_mut(..len) {
            d.copy_from_slice(fixed);
        }
        if self.enc {
            let Some(r) = self.iv.get_mut(len..self.ivlen) else {
                return Err(Error::Silent);
            };
            if !crate::rand::fill(self.rng.as_ref(), r) {
                return Err(Error::Silent);
            }
            self.iv_gen_rand = true;
        }
        self.iv_gen = true;
        self.iv_state = IvState::Buffered;
        Ok(())
    }

    /// `gcm_cipher_internal`: the output (from the output's start) and its length.
    fn internal(&mut self, io: Io<'_>) -> Result<Output, Error> {
        if self.tls_aad_len.is_some() {
            return self.tls_cipher(io);
        }
        if !self.key_set || self.iv_state == IvState::Finished {
            return Err(Error::Silent);
        }
        if self.iv_state == IvState::Uninitialised && (!self.enc || !self.iv_generate(0)) {
            return Err(Error::Silent);
        }
        if self.iv_state == IvState::Buffered {
            self.hw_setiv()?;
            self.iv_state = IvState::Copied;
        }
        let (Some(k), Some(g)) = (self.key.as_ref(), self.gcm.as_mut()) else {
            return Err(Error::Silent);
        };
        let Some(input) = io.input else {
            // The final: the tag must be set first when decrypting.
            if !self.enc && self.taglen.is_none() {
                return Err(Error::Silent);
            }
            let t = g.tag();
            if self.enc {
                *self.buf = t;
                self.taglen = Some(TAG_LEN);
            } else {
                let n = self.taglen.unwrap_or(0);
                let (Some(a), Some(b)) = (t.get(..n), self.buf.get(..n)) else {
                    return Err(Error::Silent);
                };
                if !ct_eq(a, b) {
                    return Err(Error::Silent);
                }
            }
            self.iv_state = IvState::Finished;
            return Ok(Output::new(Vec::new(), 0));
        };
        if !io.out {
            g.aad(input).map_err(|_| Error::Silent)?;
            return Ok(Output::new(Vec::new(), input.len()));
        }
        let mut data = input.to_vec();
        g.crypt(k, &mut data, self.enc).map_err(|_| Error::Silent)?;
        let len = data.len();
        Ok(Output::new(data, len))
    }

    /// `gcm_tls_cipher`: a record in place: the explicit IV, the payload, and the tag.
    fn tls_cipher(&mut self, io: Io<'_>) -> Result<Output, Error> {
        let r = self.tls_record(io);
        self.iv_state = IvState::Finished;
        self.tls_aad_len = None;
        r
    }

    fn tls_record(&mut self, io: Io<'_>) -> Result<Output, Error> {
        if !self.key_set {
            return Err(Error::Silent);
        }
        let Some(input) = io.input else {
            return Err(Error::Silent);
        };
        if !io.in_place || input.len() < TLS_EXPLICIT_IV_LEN + TAG_LEN {
            return Err(Error::Silent);
        }
        if self.enc {
            self.tls_enc_records = self.tls_enc_records.wrapping_add(1);
            if self.tls_enc_records == 0 {
                return Err(Error::TooManyRecords);
            }
        }
        let mut rec = Zeroizing::new(input.to_vec());
        let (explicit, rest) = rec.split_at_mut(TLS_EXPLICIT_IV_LEN);
        if self.enc {
            explicit.copy_from_slice(&self.iv_gen(TLS_EXPLICIT_IV_LEN)?);
        } else {
            self.set_iv_inv(explicit)?;
        }
        let plen = rest.len().saturating_sub(TAG_LEN);
        let (payload, tag) = rest.split_at_mut(plen);
        let aad = Zeroizing::new(self.buf.get(..TLS1_AAD_LEN).unwrap_or_default().to_vec());
        let (Some(k), Some(g)) = (self.key.as_ref(), self.gcm.as_mut()) else {
            return Err(Error::Silent);
        };
        g.aad(&aad).map_err(|_| Error::Silent)?;
        g.crypt(k, payload, self.enc).map_err(|_| Error::Silent)?;
        self.taglen = Some(TAG_LEN);
        let t = g.tag();
        if self.enc {
            tag.copy_from_slice(&t);
            let len = rec.len();
            return Ok(Output::new(rec.to_vec(), len));
        }
        if !ct_eq(&t, tag) {
            payload.zeroize();
            let mut o = Output::new(
                rec.get(..TLS_EXPLICIT_IV_LEN.saturating_add(plen))
                    .unwrap_or_default()
                    .to_vec(),
                0,
            );
            o.failed = Some(Error::Silent);
            return Ok(o);
        }
        Ok(Output::new(
            rec.get(..TLS_EXPLICIT_IV_LEN.saturating_add(plen))
                .unwrap_or_default()
                .to_vec(),
            plen,
        ))
    }

    /// `ossl_gcm_stream_update`.
    pub fn update(&mut self, io: Io<'_>) -> Result<Output, Raised> {
        crate::dit::with(|| self.update_dit(io))
    }

    /// [`Self::update`]'s work.
    fn update_dit(&mut self, io: Io<'_>) -> Result<Output, Raised> {
        if io.inl == 0 {
            return Ok(Output::new(Vec::new(), 0));
        }
        if io.outsize < io.inl {
            return Err(Error::OutputBufferTooSmall.into());
        }
        let o = self
            .internal(io)
            .map_err(|e| wrap(e, Error::CipherOperationFailed))?;
        Ok(fail_as(o, Error::CipherOperationFailed))
    }

    /// `ossl_gcm_stream_final`.
    pub fn finalize(&mut self) -> Result<Output, Error> {
        crate::dit::with(|| self.finalize_dit())
    }

    /// [`Self::finalize`]'s work.
    fn finalize_dit(&mut self) -> Result<Output, Error> {
        let io = Io {
            input: None,
            inl: 0,
            out: true,
            in_place: false,
            outsize: 0,
        };
        let o = self.internal(io)?;
        if o.failed.is_some() {
            return Ok(o);
        }
        Ok(Output::new(Vec::new(), 0))
    }

    /// `ossl_gcm_cipher`.
    pub fn cipher(&mut self, io: Io<'_>) -> Result<Output, Error> {
        crate::dit::with(|| self.cipher_dit(io))
    }

    /// [`Self::cipher`]'s work.
    fn cipher_dit(&mut self, io: Io<'_>) -> Result<Output, Error> {
        if io.outsize < io.inl {
            return Err(Error::OutputBufferTooSmall);
        }
        let mut o = self.internal(io)?;
        if o.failed.is_none() {
            o.len = io.inl;
        }
        Ok(o)
    }
}

/// What a failing provider function raises: an error from inside (or none, `Silent`), then
/// the one the function itself adds, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Raised {
    /// The first error.
    pub first: Error,
    /// The function's own error after it.
    pub then: Option<Error>,
}

impl From<Error> for Raised {
    fn from(first: Error) -> Self {
        Self { first, then: None }
    }
}

/// An inner failure, then `outer`.
fn wrap(first: Error, outer: Error) -> Raised {
    Raised {
        first,
        then: Some(outer),
    }
}

/// A failure after output: the outer function's error.
fn fail_as(mut o: Output, outer: Error) -> Output {
    if o.failed.is_some() {
        o.failed = Some(outer);
    }
    o
}

// -------------------------------------------------------------------------------------------
// CCM

/// `CCM128_CONTEXT` without the key.
#[derive(Clone)]
struct Ccm128 {
    nonce: Zeroizing<[u8; 16]>,
    cmac: Zeroizing<[u8; 16]>,
    blocks: u64,
}

impl Ccm128 {
    /// A context before `CRYPTO_ccm128_init`: all zeros, as the reference allocates it, so
    /// until a key is set its first octet says M is 2 and L is 1.
    fn zeroed() -> Self {
        Self {
            nonce: Zeroizing::new([0; 16]),
            cmac: Zeroizing::new([0; 16]),
            blocks: 0,
        }
    }

    /// `CRYPTO_ccm128_init`: the tag and length sizes go into the first octet.
    fn new(m: usize, l: usize) -> Self {
        let lbits = u8::try_from(l.wrapping_sub(1) & 7).unwrap_or(0);
        let mbits = u8::try_from((m.wrapping_sub(2) / 2) & 7).unwrap_or(0);
        let mut nonce = [0u8; 16];
        nonce[0] = lbits | (mbits << 3);
        Self {
            nonce: Zeroizing::new(nonce),
            cmac: Zeroizing::new([0; 16]),
            blocks: 0,
        }
    }

    /// `CRYPTO_ccm128_init` on a context in use: as `new`, but the CMAC stays, so a tag computed
    /// before the key was set again can still be read, as in the reference.
    fn reinit(&mut self, m: usize, l: usize) {
        let cmac = *self.cmac;
        *self = Self::new(m, l);
        *self.cmac = cmac;
    }

    /// The stored L (its value less one).
    fn l(&self) -> usize {
        usize::from(at(&self.nonce[..], 0) & 7)
    }

    /// `CRYPTO_ccm128_setiv`: an error for a short nonce.
    fn setiv(&mut self, nonce: &[u8], mlen: usize) -> Result<(), ()> {
        let l = self.l();
        let n = 14usize.saturating_sub(l);
        if nonce.len() < n {
            return Err(());
        }
        let m = u64::try_from(mlen).map_err(|_| ())?.to_be_bytes();
        let (head, tail) = self.nonce.split_at_mut(8);
        if l >= 3 {
            tail.copy_from_slice(&m);
        } else {
            let (hi, lo) = tail.split_at_mut(4);
            hi.fill(0);
            let (_, m_lo) = m.split_at(4);
            lo.copy_from_slice(m_lo);
        }
        put(head, 0, at(head, 0) & !0x40);
        if let (Some(d), Some(s)) = (self.nonce.get_mut(1..n.saturating_add(1)), nonce.get(..n)) {
            d.copy_from_slice(s);
        }
        Ok(())
    }

    fn encrypt_cmac(&mut self, key: &Key) -> Result<(), Error> {
        let mut c = *self.cmac;
        key.encrypt(&mut c)?;
        *self.cmac = c;
        Ok(())
    }

    /// `CRYPTO_ccm128_aad`.
    fn aad(&mut self, key: &Key, aad: &[u8]) -> Result<(), Error> {
        if aad.is_empty() {
            return Ok(());
        }
        let f = at(&self.nonce[..], 0) | 0x40;
        put(&mut self.nonce[..], 0, f);
        let mut c = *self.nonce;
        key.encrypt(&mut c)?;
        *self.cmac = c;
        self.blocks = self.blocks.wrapping_add(1);
        let alen = aad.len();
        let alen64 = u64::try_from(alen).unwrap_or(u64::MAX);
        let prefix: Vec<u8> = if alen < 0x10000 - 0x100 {
            u16::try_from(alen).unwrap_or(0).to_be_bytes().to_vec()
        } else if alen64 >= 1u64 << 32 {
            let mut v = vec![0xff, 0xff];
            v.extend_from_slice(&alen64.to_be_bytes());
            v
        } else {
            let mut v = vec![0xff, 0xfe];
            v.extend_from_slice(&u32::try_from(alen).unwrap_or(0).to_be_bytes());
            v
        };
        let mut i = prefix.len();
        for (c, p) in self.cmac.iter_mut().zip(prefix.iter()) {
            *c ^= p;
        }
        let mut data = aad;
        loop {
            while i < 16 {
                let Some((&b, rest)) = data.split_first() else {
                    break;
                };
                if let Some(c) = self.cmac.get_mut(i) {
                    *c ^= b;
                }
                data = rest;
                i = i.wrapping_add(1);
            }
            self.encrypt_cmac(key)?;
            self.blocks = self.blocks.wrapping_add(1);
            i = 0;
            if data.is_empty() {
                break;
            }
        }
        Ok(())
    }

    /// `ctr64_inc` of the nonce's last 8 octets.
    fn inc(&mut self) {
        let (_, ctr) = self.nonce.split_at_mut(8);
        for b in ctr.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }

    /// `CRYPTO_ccm128_encrypt`/`_decrypt` in place: fails for a length other than the one
    /// set, and (encrypting) past the limit.
    fn crypt(&mut self, key: &Key, data: &mut [u8], enc: bool) -> Result<(), Error> {
        let flags0 = at(&self.nonce[..], 0);
        if flags0 & 0x40 == 0 {
            let mut c = *self.nonce;
            key.encrypt(&mut c)?;
            *self.cmac = c;
            if enc {
                self.blocks = self.blocks.wrapping_add(1);
            }
        }
        let l = usize::from(flags0 & 7);
        put(&mut self.nonce[..], 0, flags0 & 7);
        let start = 15usize.saturating_sub(l);
        let mut n: u64 = 0;
        if let Some(len_octets) = self.nonce.get_mut(start..15) {
            for b in len_octets.iter_mut() {
                n |= u64::from(*b);
                *b = 0;
                n = n.wrapping_shl(8);
            }
        }
        n |= u64::from(at(&self.nonce[..], 15));
        put(&mut self.nonce[..], 15, 1);
        if usize::try_from(n).ok() != Some(data.len()) {
            return Err(Error::Silent);
        }
        if enc {
            let len = u64::try_from(data.len()).map_err(|_| Error::Silent)?;
            self.blocks = self.blocks.wrapping_add((len.wrapping_add(15) >> 3) | 1);
            if self.blocks > 1u64 << 61 {
                return Err(Error::Silent);
            }
        }
        for chunk in data.chunks_mut(16) {
            let mut s = *self.nonce;
            if enc {
                for (c, x) in self.cmac.iter_mut().zip(chunk.iter()) {
                    *c ^= x;
                }
                self.encrypt_cmac(key)?;
                key.encrypt(&mut s)?;
                if chunk.len() == 16 {
                    self.inc();
                }
                for (x, k) in chunk.iter_mut().zip(s.iter()) {
                    *x ^= k;
                }
            } else {
                key.encrypt(&mut s)?;
                if chunk.len() == 16 {
                    self.inc();
                }
                for (x, k) in chunk.iter_mut().zip(s.iter()) {
                    *x ^= k;
                }
                for (c, x) in self.cmac.iter_mut().zip(chunk.iter()) {
                    *c ^= x;
                }
                self.encrypt_cmac(key)?;
            }
            s.zeroize();
        }
        if let Some(t) = self.nonce.get_mut(start..) {
            t.fill(0);
        }
        let mut s = *self.nonce;
        key.encrypt(&mut s)?;
        xor16(&mut self.cmac, &s);
        put(&mut self.nonce[..], 0, flags0);
        Ok(())
    }

    /// `CRYPTO_ccm128_tag`: the tag if `len` is the M set with the key.
    fn tag(&self, len: usize) -> Option<&[u8]> {
        let m = usize::from((at(&self.nonce[..], 0) >> 3) & 7)
            .wrapping_mul(2)
            .wrapping_add(2);
        if len != m {
            return None;
        }
        self.cmac.get(..m)
    }
}

/// A CCM context (`PROV_CCM_CTX`).
#[derive(Clone)]
pub struct Ccm {
    algorithm: BlockAlgorithm,
    enc: bool,
    key_set: bool,
    iv_set: bool,
    tag_set: bool,
    len_set: bool,
    l: usize,
    m: usize,
    keylen: usize,
    tls_aad_len: Option<usize>,
    tls_aad_pad_sz: usize,
    iv: Zeroizing<[u8; 16]>,
    /// The tag, or the TLS AAD.
    buf: Zeroizing<[u8; 16]>,
    key: Option<Key>,
    ccm: Ccm128,
}

impl Ccm {
    /// `ossl_ccm_initctx`.
    pub fn new(algorithm: BlockAlgorithm, keylen: usize) -> Self {
        Self {
            algorithm,
            enc: false,
            key_set: false,
            iv_set: false,
            tag_set: false,
            len_set: false,
            l: 8,
            m: 12,
            keylen,
            tls_aad_len: None,
            tls_aad_pad_sz: 0,
            iv: Zeroizing::new([0; 16]),
            buf: Zeroizing::new([0; 16]),
            key: None,
            ccm: Ccm128::zeroed(),
        }
    }

    /// The IV length (15 - L).
    pub fn iv_len(&self) -> usize {
        15usize.saturating_sub(self.l)
    }

    /// The key length.
    pub fn key_len(&self) -> usize {
        self.keylen
    }

    /// The tag length (M).
    pub fn tag_len(&self) -> usize {
        self.m
    }

    /// The TLS AAD's padding.
    pub fn tls_aad_pad(&self) -> usize {
        self.tls_aad_pad_sz
    }

    /// The IV buffer (16 octets: the IV, then what's left of the buffer).
    pub fn iv_buffer(&mut self) -> &mut [u8; 16] {
        &mut self.iv
    }

    /// `ccm_init` before the parameters.
    pub fn init(&mut self, enc: bool, key: Option<&[u8]>, iv: Option<&[u8]>) -> Result<(), Error> {
        crate::dit::with(|| self.init_dit(enc, key, iv))
    }

    /// [`Self::init`]'s work.
    fn init_dit(&mut self, enc: bool, key: Option<&[u8]>, iv: Option<&[u8]>) -> Result<(), Error> {
        self.enc = enc;
        if let Some(iv) = iv {
            if iv.len() != self.iv_len() {
                return Err(Error::InvalidIvLength);
            }
            if let Some(d) = self.iv.get_mut(..iv.len()) {
                d.copy_from_slice(iv);
            }
            self.iv_set = true;
        }
        if let Some(key) = key {
            if key.len() != self.keylen {
                return Err(Error::InvalidKeyLength);
            }
            self.key = Some(Key::new(self.algorithm, key)?);
            self.ccm.reinit(self.m, self.l);
            self.key_set = true;
        }
        Ok(())
    }

    /// The `tag` parameter: a length (with no data) or the expected tag (decrypting).
    pub fn set_tag(&mut self, tag: Option<&[u8]>, size: usize) -> Result<(), Error> {
        if size & 1 != 0 || !(4..=16).contains(&size) {
            return Err(Error::InvalidTagLength);
        }
        if let Some(t) = tag {
            if self.enc {
                return Err(Error::TagNotNeeded);
            }
            if let Some(d) = self.buf.get_mut(..t.len()) {
                d.copy_from_slice(t);
            }
            self.tag_set = true;
        }
        self.m = size;
        Ok(())
    }

    /// The `ivlen` parameter: L = 15 - it, 2 to 8.
    pub fn set_iv_len(&mut self, sz: usize) -> Result<(), Error> {
        let l = 15usize.wrapping_sub(sz);
        if !(2..=8).contains(&l) {
            return Err(Error::InvalidIvLength);
        }
        if self.l != l {
            self.l = l;
            self.iv_set = false;
        }
        Ok(())
    }

    /// `ccm_tls_init`.
    pub fn tls_init(&mut self, aad: &[u8]) -> Option<usize> {
        if aad.len() != TLS1_AAD_LEN {
            return None;
        }
        if let Some(d) = self.buf.get_mut(..TLS1_AAD_LEN) {
            d.copy_from_slice(aad);
        }
        self.tls_aad_len = Some(TLS1_AAD_LEN);
        let mut len = usize::from(u16::from_be_bytes([
            at(&self.buf[..], 11),
            at(&self.buf[..], 12),
        ]));
        len = len.checked_sub(TLS_EXPLICIT_IV_LEN)?;
        if !self.enc {
            len = len.checked_sub(self.m)?;
        }
        let [h, l] = u16::try_from(len).ok()?.to_be_bytes();
        put(&mut self.buf[..], 11, h);
        put(&mut self.buf[..], 12, l);
        self.tls_aad_pad_sz = self.m;
        Some(self.m)
    }

    /// `ccm_tls_iv_set_fixed`.
    pub fn tls_iv_fixed(&mut self, fixed: &[u8]) -> Result<(), Error> {
        if fixed.len() != TLS_FIXED_IV_LEN {
            return Err(Error::InvalidIvLength);
        }
        if let Some(d) = self.iv.get_mut(..TLS_FIXED_IV_LEN) {
            d.copy_from_slice(fixed);
        }
        Ok(())
    }

    /// Whether the tag can be got: encrypting, after the data.
    pub fn tag_ready(&self) -> bool {
        self.enc && self.tag_set
    }

    /// The `tag` to get: encrypting, after the data; the IV is then used up.
    pub fn tag(&mut self, len: usize) -> Result<Vec<u8>, Error> {
        if !self.enc || !self.tag_set {
            return Err(Error::TagNotSet);
        }
        let t = self.ccm.tag(len).ok_or(Error::Silent)?.to_vec();
        self.tag_set = false;
        self.iv_set = false;
        self.len_set = false;
        Ok(t)
    }

    fn set_iv(&mut self, mlen: usize) -> Result<(), Error> {
        let n = self.iv_len();
        let iv = *self.iv;
        self.ccm
            .setiv(iv.get(..n).unwrap_or_default(), mlen)
            .map_err(|()| Error::Silent)?;
        self.len_set = true;
        Ok(())
    }

    /// `ccm_cipher_internal`.
    fn internal(&mut self, io: Io<'_>) -> Result<Output, Error> {
        if !self.key_set {
            return Err(Error::Silent);
        }
        if self.tls_aad_len.is_some() {
            return self.tls_cipher(io);
        }
        if io.input.is_none() && io.out {
            return Ok(Output::new(Vec::new(), 0));
        }
        if !self.iv_set {
            return Err(Error::Silent);
        }
        let len = io.inl;
        let Some(key) = self.key.clone() else {
            return Err(Error::Silent);
        };
        if !io.out {
            match io.input {
                None => self.set_iv(len)?,
                Some(aad) => {
                    if !self.len_set && len > 0 {
                        return Err(Error::Silent);
                    }
                    self.ccm.aad(&key, aad)?;
                }
            }
            return Ok(Output::new(Vec::new(), len));
        }
        let input = io.input.unwrap_or_default();
        if !self.len_set {
            self.set_iv(len)?;
        }
        let mut data = input.to_vec();
        if self.enc {
            self.ccm.crypt(&key, &mut data, true)?;
            self.tag_set = true;
            return Ok(Output::new(data, len));
        }
        if !self.tag_set {
            return Err(Error::Silent);
        }
        if let Err(e) = self.ccm.crypt(&key, &mut data, false) {
            data.as_mut_slice().zeroize();
            let _ = e;
            let mut o = Output::new(data, 0);
            o.failed = Some(Error::Silent);
            return Ok(o);
        }
        let ok = match (self.ccm.tag(self.m), self.buf.get(..self.m)) {
            (Some(t), Some(e)) => ct_eq(t, e),
            _ => false,
        };
        if !ok {
            data.as_mut_slice().zeroize();
            let mut o = Output::new(data, 0);
            o.failed = Some(Error::Silent);
            return Ok(o);
        }
        self.iv_set = false;
        self.tag_set = false;
        self.len_set = false;
        Ok(Output::new(data, len))
    }

    /// `ccm_tls_cipher`: a record in place.
    fn tls_cipher(&mut self, io: Io<'_>) -> Result<Output, Error> {
        let Some(input) = io.input else {
            return Err(Error::Silent);
        };
        let m = self.m;
        let min = TLS_EXPLICIT_IV_LEN.saturating_add(m);
        if !io.out || !io.in_place || input.len() < min {
            return Err(Error::Silent);
        }
        let mut rec = Zeroizing::new(input.to_vec());
        let len = rec.len().saturating_sub(min);
        let (explicit, rest) = rec.split_at_mut(TLS_EXPLICIT_IV_LEN);
        if let (true, Some(seq)) = (self.enc, self.buf.get(..TLS_EXPLICIT_IV_LEN)) {
            explicit.copy_from_slice(seq);
        }
        if let Some(d) = self
            .iv
            .get_mut(TLS_FIXED_IV_LEN..TLS_FIXED_IV_LEN.saturating_add(TLS_EXPLICIT_IV_LEN))
        {
            d.copy_from_slice(explicit);
        }
        self.set_iv(len)?;
        let Some(key) = self.key.clone() else {
            return Err(Error::Silent);
        };
        let aad = Zeroizing::new(self.buf.get(..TLS1_AAD_LEN).unwrap_or_default().to_vec());
        self.ccm.aad(&key, &aad)?;
        let (payload, tag) = rest.split_at_mut(len);
        if self.enc {
            self.ccm.crypt(&key, payload, true)?;
            let t = self.ccm.tag(m).ok_or(Error::Silent)?;
            tag.copy_from_slice(t);
            let n = rec.len();
            return Ok(Output::new(rec.to_vec(), n));
        }
        let r = self.ccm.crypt(&key, payload, false);
        let ok = r.is_ok() && self.ccm.tag(m).is_some_and(|t| ct_eq(t, tag));
        if !ok {
            payload.zeroize();
        }
        let head = rec
            .get(..TLS_EXPLICIT_IV_LEN.saturating_add(len))
            .unwrap_or_default()
            .to_vec();
        if !ok {
            let mut o = Output::new(head, 0);
            o.failed = Some(Error::Silent);
            return Ok(o);
        }
        Ok(Output::new(head, len))
    }

    /// `ossl_ccm_stream_update`.
    pub fn update(&mut self, io: Io<'_>) -> Result<Output, Raised> {
        crate::dit::with(|| self.update_dit(io))
    }

    /// [`Self::update`]'s work.
    fn update_dit(&mut self, io: Io<'_>) -> Result<Output, Raised> {
        if io.outsize < io.inl {
            return Err(Error::OutputBufferTooSmall.into());
        }
        let o = self
            .internal(io)
            .map_err(|e| wrap(e, Error::CipherOperationFailed))?;
        Ok(fail_as(o, Error::CipherOperationFailed))
    }

    /// `ossl_ccm_stream_final`: an update of nothing if the data hasn't been processed.
    pub fn finalize(&mut self) -> Result<Output, Error> {
        crate::dit::with(|| self.finalize_dit())
    }

    /// [`Self::finalize`]'s work.
    fn finalize_dit(&mut self) -> Result<Output, Error> {
        if !self.key_set {
            return Err(Error::Silent);
        }
        if self.iv_set && (!self.enc || !self.tag_set) {
            let io = Io {
                input: Some(&[]),
                inl: 0,
                out: true,
                in_place: false,
                outsize: 0,
            };
            let o = self.internal(io)?;
            if o.failed.is_some() {
                return Err(Error::Silent);
            }
        }
        Ok(Output::new(Vec::new(), 0))
    }

    /// `ossl_ccm_cipher`.
    pub fn cipher(&mut self, io: Io<'_>) -> Result<Output, Error> {
        crate::dit::with(|| self.cipher_dit(io))
    }

    /// [`Self::cipher`]'s work.
    fn cipher_dit(&mut self, io: Io<'_>) -> Result<Output, Error> {
        if io.input.is_none() {
            return self.finalize();
        }
        if io.outsize < io.inl {
            return Err(Error::OutputBufferTooSmall);
        }
        let mut o = self.internal(io)?;
        if o.failed.is_none() {
            o.len = io.inl;
        }
        Ok(o)
    }
}

// -------------------------------------------------------------------------------------------
// OCB

/// `ocb_double`: multiplication by x in GF(2^128), constant time.
fn ocb_double(b: &[u8; 16]) -> [u8; 16] {
    let mask = (b[0] >> 7).wrapping_neg() & 0x87;
    let mut out = shl(b, 1);
    out[15] ^= mask;
    out
}

/// `ocb_block_lshift` of 16 octets by `shift` (0 to 7) bits, taking the carry from `next`.
fn shl(b: &[u8; 16], shift: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    for (o, &x) in out.iter_mut().zip(b.iter()).rev() {
        *o = x.wrapping_shl(shift) | carry;
        carry = x.checked_shr(8u32.wrapping_sub(shift)).unwrap_or(0);
    }
    out
}

/// The number of trailing zero bits of `n` (at least 1).
fn ntz(n: u64) -> usize {
    usize::try_from(n.trailing_zeros()).unwrap_or(0)
}

/// `OCB128_CONTEXT` without the keys.
#[derive(Clone)]
struct Ocb128 {
    l_star: Zeroizing<[u8; 16]>,
    l_dollar: Zeroizing<[u8; 16]>,
    l: Vec<[u8; 16]>,
    offset: Zeroizing<[u8; 16]>,
    offset_aad: Zeroizing<[u8; 16]>,
    sum: Zeroizing<[u8; 16]>,
    checksum: Zeroizing<[u8; 16]>,
    blocks_hashed: u64,
    blocks_processed: u64,
}

impl Drop for Ocb128 {
    fn drop(&mut self) {
        self.l.zeroize();
    }
}

impl Ocb128 {
    /// `CRYPTO_ocb128_init`: L_*, L_$, and L_0 to L_4.
    fn new(key: &Key) -> Result<Self, Error> {
        let mut l_star = [0u8; 16];
        key.encrypt(&mut l_star)?;
        let l_dollar = ocb_double(&l_star);
        let mut l = vec![ocb_double(&l_dollar)];
        for _ in 0..4 {
            let next = ocb_double(l.last().ok_or(Error::Internal)?);
            l.push(next);
        }
        Ok(Self {
            l_star: Zeroizing::new(l_star),
            l_dollar: Zeroizing::new(l_dollar),
            l,
            offset: Zeroizing::new([0; 16]),
            offset_aad: Zeroizing::new([0; 16]),
            sum: Zeroizing::new([0; 16]),
            checksum: Zeroizing::new([0; 16]),
            blocks_hashed: 0,
            blocks_processed: 0,
        })
    }

    /// `ocb_lookup_l`, growing the table.
    fn lookup(&mut self, idx: usize) -> Result<[u8; 16], Error> {
        while self.l.len() <= idx {
            let next = ocb_double(self.l.last().ok_or(Error::Internal)?);
            self.l.push(next);
        }
        self.l.get(idx).copied().ok_or(Error::Internal)
    }

    /// `CRYPTO_ocb128_setiv`: -1 for an IV of 0 or over 15 octets, or a tag of 0 or over 16.
    fn setiv(&mut self, key: &Key, iv: &[u8], taglen: usize) -> Result<(), Error> {
        if !(1..=15).contains(&iv.len()) || !(1..=16).contains(&taglen) {
            return Err(Error::Silent);
        }
        *self.offset = [0; 16];
        *self.offset_aad = [0; 16];
        *self.sum = [0; 16];
        *self.checksum = [0; 16];
        self.blocks_hashed = 0;
        self.blocks_processed = 0;
        let mut nonce = [0u8; 16];
        nonce[0] = u8::try_from((taglen.wrapping_mul(8) % 128) << 1).unwrap_or(0);
        let pos = 16usize.saturating_sub(iv.len());
        if let Some(d) = nonce.get_mut(pos..) {
            d.copy_from_slice(iv);
        }
        if let Some(b) = nonce.get_mut(15usize.saturating_sub(iv.len())) {
            *b |= 1;
        }
        let mut ktop = nonce;
        ktop[15] &= 0xc0;
        key.encrypt(&mut ktop)?;
        let mut stretch = [0u8; 24];
        stretch[..16].copy_from_slice(&ktop);
        for (i, s) in stretch[16..].iter_mut().enumerate() {
            *s = at(&ktop, i) ^ at(&ktop, i.wrapping_add(1));
        }
        let bottom = usize::from(nonce[15] & 0x3f);
        let (byte, bits) = (bottom / 8, u32::try_from(bottom % 8).unwrap_or(0));
        let mut window = [0u8; 16];
        if let Some(w) = stretch.get(byte..byte.saturating_add(16)) {
            window.copy_from_slice(w);
        }
        let mut off = shl(&window, bits);
        let next = at(&stretch, byte.saturating_add(16));
        if bits > 0 {
            let sh = 8u32.wrapping_sub(bits);
            let mask = 0xffu8.checked_shl(sh).unwrap_or(0);
            off[15] |= (next & mask).checked_shr(sh).unwrap_or(0);
        }
        *self.offset = off;
        Ok(())
    }

    /// `CRYPTO_ocb128_aad`.
    fn aad(&mut self, key: &Key, aad: &[u8]) -> Result<(), Error> {
        let (blocks, last) = aad.as_chunks::<16>();
        for b in blocks {
            self.blocks_hashed = self.blocks_hashed.wrapping_add(1);
            let l = self.lookup(ntz(self.blocks_hashed))?;
            xor16(&mut self.offset_aad, &l);
            let mut t = [0u8; 16];
            t.copy_from_slice(b);
            xor16(&mut t, &self.offset_aad);
            key.encrypt(&mut t)?;
            xor16(&mut self.sum, &t);
        }
        if !last.is_empty() {
            let ls = *self.l_star;
            xor16(&mut self.offset_aad, &ls);
            let mut t = [0u8; 16];
            for (d, s) in t.iter_mut().zip(last) {
                *d = *s;
            }
            put(&mut t, last.len(), 0x80);
            xor16(&mut t, &self.offset_aad);
            key.encrypt(&mut t)?;
            xor16(&mut self.sum, &t);
        }
        Ok(())
    }

    /// `CRYPTO_ocb128_encrypt`/`_decrypt` in place.
    fn crypt(&mut self, key: &Key, data: &mut [u8], enc: bool) -> Result<(), Error> {
        let (blocks, last) = data.as_chunks_mut::<16>();
        for b in blocks {
            self.blocks_processed = self.blocks_processed.wrapping_add(1);
            let l = self.lookup(ntz(self.blocks_processed))?;
            xor16(&mut self.offset, &l);
            let mut t = [0u8; 16];
            t.copy_from_slice(b);
            if enc {
                xor16(&mut self.checksum, &t);
            }
            xor16(&mut t, &self.offset);
            if enc {
                key.encrypt(&mut t)?;
            } else {
                key.decrypt(&mut t)?;
            }
            xor16(&mut t, &self.offset);
            if !enc {
                xor16(&mut self.checksum, &t);
            }
            *b = t;
        }
        if !last.is_empty() {
            let ls = *self.l_star;
            xor16(&mut self.offset, &ls);
            let mut pad = *self.offset;
            key.encrypt(&mut pad)?;
            let mut p = [0u8; 16];
            for ((x, k), q) in last.iter_mut().zip(pad.iter()).zip(p.iter_mut()) {
                if enc {
                    *q = *x;
                }
                *x ^= k;
                if !enc {
                    *q = *x;
                }
            }
            put(&mut p, last.len(), 0x80);
            xor16(&mut self.checksum, &p);
        }
        Ok(())
    }

    /// `ocb_finish`'s tag: ENCIPHER(K, Checksum xor Offset xor L_$) xor Sum.
    fn tag(&self, key: &Key) -> Result<[u8; 16], Error> {
        let mut t = *self.checksum;
        xor16(&mut t, &self.offset);
        xor16(&mut t, &self.l_dollar);
        key.encrypt(&mut t)?;
        xor16(&mut t, &self.sum);
        Ok(t)
    }
}

/// An OCB context (`PROV_AES_OCB_CTX`).
#[derive(Clone)]
pub struct Ocb {
    keylen: usize,
    ivlen: usize,
    oiv: [u8; 16],
    iv: [u8; 16],
    enc: bool,
    iv_state: IvState,
    key_set: bool,
    taglen: usize,
    tag: Zeroizing<[u8; 16]>,
    aad_buf: Zeroizing<[u8; 16]>,
    aad_len: usize,
    data_buf: Zeroizing<[u8; 16]>,
    data_len: usize,
    key: Option<Key>,
    ocb: Option<Ocb128>,
}

impl Ocb {
    /// `aes_ocb_newctx`: a 12-octet IV and a 16-octet tag.
    pub fn new(keylen: usize) -> Self {
        Self {
            keylen,
            ivlen: GCM_IV_DEFAULT,
            oiv: [0; 16],
            iv: [0; 16],
            enc: false,
            iv_state: IvState::Uninitialised,
            key_set: false,
            taglen: TAG_LEN,
            tag: Zeroizing::new([0; 16]),
            aad_buf: Zeroizing::new([0; 16]),
            aad_len: 0,
            data_buf: Zeroizing::new([0; 16]),
            data_len: 0,
            key: None,
            ocb: None,
        }
    }

    /// The IV length.
    pub fn iv_len(&self) -> usize {
        self.ivlen
    }

    /// The key length.
    pub fn key_len(&self) -> usize {
        self.keylen
    }

    /// The tag length.
    pub fn tag_len(&self) -> usize {
        self.taglen
    }

    /// The IV as set (`iv`) and its copy (`updated-iv`), 16 octets each.
    pub fn ivs(&mut self) -> (&mut [u8; 16], &mut [u8; 16]) {
        (&mut self.oiv, &mut self.iv)
    }

    /// `aes_ocb_init` before the parameters.
    pub fn init(&mut self, enc: bool, key: Option<&[u8]>, iv: Option<&[u8]>) -> Result<(), Error> {
        crate::dit::with(|| self.init_dit(enc, key, iv))
    }

    /// [`Self::init`]'s work.
    fn init_dit(&mut self, enc: bool, key: Option<&[u8]>, iv: Option<&[u8]>) -> Result<(), Error> {
        self.aad_len = 0;
        self.data_len = 0;
        self.enc = enc;
        if let Some(iv) = iv {
            if iv.len() != self.ivlen {
                if iv.is_empty() || iv.len() > 15 {
                    return Err(Error::InvalidIvLength);
                }
                self.ivlen = iv.len();
            }
            if let (Some(a), Some(b)) = (self.iv.get_mut(..iv.len()), self.oiv.get_mut(..iv.len()))
            {
                a.copy_from_slice(iv);
                b.copy_from_slice(iv);
            }
            self.iv_state = IvState::Buffered;
        }
        if let Some(key) = key {
            if key.len() != self.keylen {
                return Err(Error::InvalidKeyLength);
            }
            let k = Key::new(BlockAlgorithm::Aes, key)?;
            self.ocb = Some(Ocb128::new(&k)?);
            self.key = Some(k);
            self.key_set = true;
        }
        Ok(())
    }

    /// The `tag` parameter: a length (no data, at most 16) or the expected tag.
    pub fn set_tag(&mut self, tag: Option<&[u8]>, size: usize) -> Result<(), Error> {
        match tag {
            None => {
                if size > TAG_LEN {
                    return Err(Error::InvalidTagLength);
                }
                self.taglen = size;
            }
            Some(t) => {
                if self.enc {
                    return Err(Error::PassedInvalidArgument);
                }
                if t.len() != self.taglen {
                    return Err(Error::InvalidTagLength);
                }
                if let Some(d) = self.tag.get_mut(..t.len()) {
                    d.copy_from_slice(t);
                }
            }
        }
        Ok(())
    }

    /// The `ivlen` parameter: 1 to 15 (anything else fails without an error).
    pub fn set_iv_len(&mut self, sz: usize) -> Result<(), Error> {
        if !(1..=15).contains(&sz) {
            return Err(Error::Silent);
        }
        if self.ivlen != sz {
            self.ivlen = sz;
            self.iv_state = IvState::Uninitialised;
        }
        Ok(())
    }

    /// The tag to get: encrypting, with room for exactly the tag length.
    pub fn tag(&self, size: usize) -> Result<&[u8], Error> {
        if !self.enc || size != self.taglen {
            return Err(Error::InvalidTagLength);
        }
        self.tag.get(..size).ok_or(Error::InvalidTagLength)
    }

    /// `update_iv`.
    fn update_iv(&mut self) -> bool {
        match self.iv_state {
            IvState::Finished | IvState::Uninitialised => false,
            IvState::Copied => true,
            IvState::Buffered => {
                let (Some(k), Some(o)) = (self.key.as_ref(), self.ocb.as_mut()) else {
                    return false;
                };
                let iv = self.iv.get(..self.ivlen).unwrap_or_default();
                if o.setiv(k, iv, self.taglen).is_err() {
                    return false;
                }
                self.iv_state = IvState::Copied;
                true
            }
        }
    }

    fn ocb_crypt(&mut self, data: &mut [u8]) -> Result<(), Error> {
        let (Some(k), Some(o)) = (self.key.as_ref(), self.ocb.as_mut()) else {
            return Err(Error::CipherOperationFailed);
        };
        o.crypt(k, data, self.enc)
    }

    fn ocb_aad(&mut self, data: &[u8]) -> Result<(), Error> {
        let (Some(k), Some(o)) = (self.key.as_ref(), self.ocb.as_mut()) else {
            return Err(Error::CipherOperationFailed);
        };
        o.aad(k, data)
    }

    /// `aes_ocb_block_update`: whole blocks of data (or of AAD, with no output), the rest
    /// buffered.
    pub fn update(&mut self, io: Io<'_>) -> Result<Output, Raised> {
        crate::dit::with(|| self.update_dit(io))
    }

    /// [`Self::update`]'s work.
    fn update_dit(&mut self, io: Io<'_>) -> Result<Output, Raised> {
        if !self.key_set || !self.update_iv() {
            return Err(Error::Silent.into());
        }
        if io.inl == 0 {
            return Ok(Output::new(Vec::new(), 0));
        }
        let Some(input) = io.input else {
            return Err(Error::Silent.into());
        };
        let aad = !io.out;
        let (mut buf, mut bufsz) = if aad {
            (*self.aad_buf, self.aad_len)
        } else {
            (*self.data_buf, self.data_len)
        };
        let mut input = input;
        let mut out: Vec<u8> = Vec::new();
        let mut outlint = 0usize;
        let nextblocks = if bufsz != 0 {
            let take = 16usize.saturating_sub(bufsz).min(input.len());
            let (head, rest) = input.split_at(take);
            if let Some(d) = buf.get_mut(bufsz..bufsz.saturating_add(take)) {
                d.copy_from_slice(head);
            }
            bufsz = bufsz.saturating_add(take);
            input = rest;
            input.len() & !15
        } else {
            input.len() & !15
        };
        let r = (|| -> Result<(), Raised> {
            if bufsz == 16 {
                if io.outsize < 16 {
                    return Err(Error::OutputBufferTooSmall.into());
                }
                let mut b = buf;
                if aad {
                    self.ocb_aad(&b)
                        .map_err(|_| wrap(Error::Silent, Error::CipherOperationFailed))?;
                } else {
                    self.ocb_crypt(&mut b)
                        .map_err(|_| wrap(Error::Silent, Error::CipherOperationFailed))?;
                    out.extend_from_slice(&b);
                }
                bufsz = 0;
                outlint = 16;
            }
            if nextblocks > 0 {
                outlint = outlint.saturating_add(nextblocks);
                if io.outsize < outlint {
                    return Err(Error::OutputBufferTooSmall.into());
                }
                let (now, rest) = input.split_at(nextblocks);
                if aad {
                    self.ocb_aad(now)
                        .map_err(|_| wrap(Error::Silent, Error::CipherOperationFailed))?;
                } else {
                    let mut d = now.to_vec();
                    self.ocb_crypt(&mut d)
                        .map_err(|_| wrap(Error::Silent, Error::CipherOperationFailed))?;
                    out.extend_from_slice(&d);
                }
                input = rest;
            }
            if !input.is_empty() {
                let end = bufsz.saturating_add(input.len());
                if end > 16 {
                    return Err(Error::Internal.into());
                }
                if let Some(d) = buf.get_mut(bufsz..end) {
                    d.copy_from_slice(input);
                }
                bufsz = end;
            }
            Ok(())
        })();
        if aad {
            *self.aad_buf = buf;
            self.aad_len = bufsz;
        } else {
            *self.data_buf = buf;
            self.data_len = bufsz;
        }
        buf.zeroize();
        r?;
        Ok(Output::new(out, outlint))
    }

    /// `aes_ocb_block_final`: the partial blocks, then the tag (made or checked).
    pub fn finalize(&mut self) -> Result<Output, Error> {
        crate::dit::with(|| self.finalize_dit())
    }

    /// [`Self::finalize`]'s work.
    fn finalize_dit(&mut self) -> Result<Output, Error> {
        if !self.key_set || !self.update_iv() {
            return Err(Error::Silent);
        }
        let mut out = Vec::new();
        if self.data_len > 0 {
            let mut d = self
                .data_buf
                .get(..self.data_len)
                .unwrap_or_default()
                .to_vec();
            self.ocb_crypt(&mut d)?;
            out = d;
            self.data_len = 0;
        }
        if self.aad_len > 0 {
            let a = Zeroizing::new(
                self.aad_buf
                    .get(..self.aad_len)
                    .unwrap_or_default()
                    .to_vec(),
            );
            self.ocb_aad(&a)?;
            self.aad_len = 0;
        }
        let (Some(k), Some(o)) = (self.key.as_ref(), self.ocb.as_ref()) else {
            return Err(Error::Silent);
        };
        if !(1..=16).contains(&self.taglen) {
            return Err(Error::Silent);
        }
        let t = o.tag(k)?;
        if self.enc {
            if let (Some(d), Some(s)) = (self.tag.get_mut(..self.taglen), t.get(..self.taglen)) {
                d.copy_from_slice(s);
            }
        } else {
            let ok = match (t.get(..self.taglen), self.tag.get(..self.taglen)) {
                (Some(a), Some(b)) => ct_eq(a, b),
                _ => false,
            };
            if !ok {
                // The partial block is written all the same.
                let mut o = Output::new(out, 0);
                o.failed = Some(Error::Silent);
                return Ok(o);
            }
        }
        self.iv_state = IvState::Finished;
        let len = out.len();
        Ok(Output::new(out, len))
    }

    /// `aes_ocb_cipher`: the mode on the input directly (NULL input finishes).
    pub fn cipher(&mut self, io: Io<'_>) -> Result<Output, Raised> {
        crate::dit::with(|| self.cipher_dit(io))
    }

    /// [`Self::cipher`]'s work.
    fn cipher_dit(&mut self, io: Io<'_>) -> Result<Output, Raised> {
        let Some(input) = io.input else {
            return self.finalize().map_err(Raised::from);
        };
        if io.outsize < io.inl {
            return Err(Error::OutputBufferTooSmall.into());
        }
        if !self.key_set || !self.update_iv() {
            return Err(Error::CipherOperationFailed.into());
        }
        let mut d = input.to_vec();
        self.ocb_crypt(&mut d)
            .map_err(|_| Raised::from(Error::CipherOperationFailed))?;
        let len = io.inl;
        Ok(Output::new(d, len))
    }
}

// -------------------------------------------------------------------------------------------
// ChaCha20-Poly1305

/// The IV length.
const CHACHA_POLY_IV: usize = 12;

/// A ChaCha20-Poly1305 context (`PROV_CHACHA20_POLY1305_CTX`).
#[derive(Clone)]
pub struct ChaChaPoly {
    enc: bool,
    key_set: bool,
    oiv: [u8; 16],
    chacha: ChaCha,
    /// The IV's three words (OpenSSL's `nonce[]`).
    nonce: [u8; 12],
    tag: Zeroizing<[u8; 16]>,
    tag_len: usize,
    tls_aad: Zeroizing<[u8; 16]>,
    tls_payload_length: Option<usize>,
    tls_aad_pad_sz: usize,
    mac_inited: bool,
    aad: bool,
    len_aad: u64,
    len_text: u64,
    poly: Option<Hash>,
    pend: Zeroizing<Vec<u8>>,
}

impl ChaChaPoly {
    /// `chacha20_poly1305_newctx`.
    pub fn new() -> Self {
        Self {
            enc: false,
            key_set: false,
            oiv: [0; 16],
            chacha: ChaCha::new(),
            nonce: [0; 12],
            tag: Zeroizing::new([0; 16]),
            tag_len: 0,
            tls_aad: Zeroizing::new([0; 16]),
            tls_payload_length: None,
            tls_aad_pad_sz: 0,
            mac_inited: false,
            aad: false,
            len_aad: 0,
            len_text: 0,
            poly: None,
            pend: Zeroizing::new(Vec::new()),
        }
    }

    /// The tag length (0 until set).
    pub fn tag_len(&self) -> usize {
        self.tag_len
    }

    /// The TLS AAD's padding.
    pub fn tls_aad_pad(&self) -> usize {
        self.tls_aad_pad_sz
    }

    /// The counter's second word: the 64-bit counter's high half.
    fn set_word1(&mut self, w: [u8; 4]) {
        let lo = self.chacha.counter & 0xffff_ffff;
        self.chacha.counter = lo | (u64::from(u32::from_le_bytes(w)) << 32);
    }

    /// The nonce words as the counter's last three.
    fn set_counter_words(&mut self, w: [u8; 12]) {
        let [a, b, c, d, rest @ ..] = w;
        self.set_word1([a, b, c, d]);
        self.chacha.nonce = rest;
    }

    fn reset_mac_state(&mut self) {
        self.len_aad = 0;
        self.len_text = 0;
        self.aad = false;
        self.mac_inited = false;
        self.tls_payload_length = None;
    }

    /// The generic init, then `initkey` and `initiv`, before the parameters.
    pub fn init(&mut self, enc: bool, key: Option<&[u8]>, iv: Option<&[u8]>) -> Result<(), Error> {
        crate::dit::with(|| self.init_dit(enc, key, iv))
    }

    /// [`Self::init`]'s work.
    fn init_dit(&mut self, enc: bool, key: Option<&[u8]>, iv: Option<&[u8]>) -> Result<(), Error> {
        self.enc = enc;
        if let Some(iv) = iv {
            if iv.len() != CHACHA_POLY_IV {
                return Err(Error::InvalidIvLength);
            }
            if let Some(d) = self.oiv.get_mut(..CHACHA_POLY_IV) {
                d.copy_from_slice(iv);
            }
        }
        if let Some(key) = key {
            let k: &[u8; 32] = key.try_into().map_err(|_| Error::InvalidKeyLength)?;
            self.reset_mac_state();
            self.chacha.key.copy_from_slice(k);
            self.chacha.partial = 0;
            self.key_set = true;
        }
        if iv.is_some() {
            self.reset_mac_state();
            let mut w = [0u8; 12];
            w.copy_from_slice(&self.oiv[..12]);
            // The 16-octet ChaCha20 IV is the nonce padded on the left: counter 0.
            self.chacha.counter = 0;
            self.set_counter_words(w);
            self.chacha.partial = 0;
            self.nonce = w;
        }
        Ok(())
    }

    /// The `tag` parameter.
    pub fn set_tag(&mut self, tag: Option<&[u8]>, size: usize) -> Result<(), Error> {
        if size == 0 || size > TAG_LEN {
            return Err(Error::InvalidTagLength);
        }
        if let Some(t) = tag {
            if self.enc {
                return Err(Error::TagNotNeeded);
            }
            if let Some(d) = self.tag.get_mut(..t.len()) {
                d.copy_from_slice(t);
            }
        }
        self.tag_len = size;
        Ok(())
    }

    /// The tag to get: encrypting, 1 to 16 octets.
    pub fn tag(&self, size: usize) -> Result<&[u8], Error> {
        if !self.enc {
            return Err(Error::TagNotSet);
        }
        if size == 0 || size > TAG_LEN {
            return Err(Error::InvalidTagLength);
        }
        self.tag.get(..size).ok_or(Error::InvalidTagLength)
    }

    /// `chacha_poly1305_tls_init`.
    pub fn tls_init(&mut self, aad: &[u8]) -> Option<usize> {
        if aad.len() != TLS1_AAD_LEN {
            return None;
        }
        if let Some(d) = self.tls_aad.get_mut(..TLS1_AAD_LEN) {
            d.copy_from_slice(aad);
        }
        let mut len = usize::from(u16::from_be_bytes([at(aad, 11), at(aad, 12)]));
        if !self.enc {
            len = len.checked_sub(TAG_LEN)?;
            let [h, l] = u16::try_from(len).ok()?.to_be_bytes();
            put(&mut self.tls_aad[..], 11, h);
            put(&mut self.tls_aad[..], 12, l);
        }
        self.tls_payload_length = Some(len);
        let mut w = self.nonce;
        for (x, y) in w[4..12].iter_mut().zip(self.tls_aad.iter()) {
            *x ^= y;
        }
        self.set_counter_words(w);
        self.mac_inited = false;
        self.tls_aad_pad_sz = TAG_LEN;
        Some(TAG_LEN)
    }

    /// `chacha_poly1305_tls_iv_set_fixed`.
    pub fn tls_iv_fixed(&mut self, fixed: &[u8]) -> Result<(), Error> {
        let w: [u8; 12] = fixed.try_into().map_err(|_| Error::InvalidIvLength)?;
        self.nonce = w;
        self.set_counter_words(w);
        Ok(())
    }

    fn poly_update(&mut self, data: &[u8]) {
        self.pend.extend_from_slice(data);
        let whole = self.pend.len() & !15;
        if whole > 0 {
            if let (Some(p), Some(b)) = (self.poly.as_mut(), self.pend.get(..whole)) {
                p.0.update_padded(b);
            }
            self.pend.drain(..whole);
        }
    }

    fn poly_final(&mut self) -> [u8; 16] {
        let last = core::mem::take(&mut *self.pend);
        let t = match self.poly.take() {
            Some(mut p) => p.0.finalize(&last),
            None => [0; 16],
        };
        let mut last = last;
        last.zeroize();
        t
    }

    /// Pads the poly1305 input with zeros to a block boundary after `n` octets.
    fn poly_pad(&mut self, n: u64) {
        let rem = usize::try_from(n % 16).unwrap_or(0);
        if rem != 0 {
            self.poly_update(
                [0u8; 16]
                    .get(..16usize.saturating_sub(rem))
                    .unwrap_or_default(),
            );
        }
    }

    /// Keys Poly1305 from the key stream's block 0 and goes on from block 1.
    fn mac_init(&mut self) -> Result<(), Error> {
        self.chacha.counter &= !0xffff_ffff;
        let mut block = Zeroizing::new([0u8; 64]);
        sym::chacha20_blocks(
            &self.chacha.key,
            self.chacha.nonce,
            self.chacha.counter,
            &mut block[..],
        )
        .map_err(|_| Error::Internal)?;
        self.poly = Some(Hash(
            sym::universal_hash(HashAlgorithm::Poly1305, block.get(..32).unwrap_or_default())
                .map_err(|_| Error::Internal)?,
        ));
        self.pend.clear();
        self.chacha.counter = (self.chacha.counter & !0xffff_ffff) | 1;
        self.chacha.partial = 0;
        Ok(())
    }

    fn lengths(&self) -> [u8; 16] {
        let mut l = [0u8; 16];
        l[..8].copy_from_slice(&self.len_aad.to_le_bytes());
        l[8..].copy_from_slice(&self.len_text.to_le_bytes());
        l
    }

    /// `chacha20_poly1305_aead_cipher`.
    fn aead(&mut self, io: Io<'_>) -> Result<Output, Error> {
        let mut plen = self.tls_payload_length;
        let inl = io.inl;
        if !self.mac_inited {
            if let (Some(p), true) = (plen, io.out) {
                if inl != p.saturating_add(TAG_LEN) {
                    return Err(Error::Silent);
                }
                return self.tls_cipher(io, p);
            }
            self.mac_init()?;
            self.len_aad = 0;
            self.len_text = 0;
            self.mac_inited = true;
            if plen.is_some() {
                let aad = *self.tls_aad;
                self.poly_update(&aad[..TLS1_AAD_LEN]);
                self.len_aad = TLS1_AAD_LEN as u64;
                self.aad = true;
            }
        }
        let mut out = Vec::new();
        let mut olen = inl;
        let mut processed = 0usize;
        if let Some(input) = io.input {
            if !io.out {
                if self.len_text != 0 {
                    return Err(Error::Silent);
                }
                self.poly_update(input);
                self.len_aad = self.len_aad.wrapping_add(u64::try_from(inl).unwrap_or(0));
                self.aad = true;
                return Ok(Output::new(Vec::new(), inl));
            }
            if self.aad {
                self.poly_pad(self.len_aad);
                self.aad = false;
            }
            self.tls_payload_length = None;
            let p = match plen {
                None => inl,
                Some(p) => {
                    if inl != p.saturating_add(TAG_LEN) {
                        return Err(Error::Silent);
                    }
                    p
                }
            };
            plen = Some(p);
            let mut d = input.get(..p).unwrap_or_default().to_vec();
            if self.enc {
                self.chacha.apply(&mut d)?;
                self.poly_update(&d);
            } else {
                self.poly_update(&d);
                self.chacha.apply(&mut d)?;
            }
            self.len_text = self.len_text.wrapping_add(u64::try_from(p).unwrap_or(0));
            out = d;
            processed = p;
        }
        let p = plen.unwrap_or(inl);
        if io.input.is_none() || inl != p {
            if self.aad {
                self.poly_pad(self.len_aad);
                self.aad = false;
            }
            self.poly_pad(self.len_text);
            let l = self.lengths();
            self.poly_update(&l);
            let temp = self.poly_final();
            if self.enc {
                *self.tag = temp;
            }
            self.mac_inited = false;
            if let (Some(input), true) = (io.input, inl != p) {
                if self.enc {
                    out.extend_from_slice(&temp);
                } else {
                    let ok = input
                        .get(processed..processed.saturating_add(TAG_LEN))
                        .is_some_and(|t| ct_eq(&temp, t));
                    if !ok {
                        out.as_mut_slice().zeroize();
                        let mut o = Output::new(out, 0);
                        o.failed = Some(Error::Silent);
                        return Ok(o);
                    }
                    olen = inl.saturating_sub(TAG_LEN);
                }
            } else if !self.enc {
                let n = self.tag_len;
                let ok = match (temp.get(..n), self.tag.get(..n)) {
                    (Some(a), Some(b)) => ct_eq(a, b),
                    _ => false,
                };
                if !ok {
                    return Err(Error::Silent);
                }
            }
        }
        Ok(Output::new(out, olen))
    }

    /// `chacha20_poly1305_tls_cipher`: a record of the payload and its tag.
    fn tls_cipher(&mut self, io: Io<'_>, plen: usize) -> Result<Output, Error> {
        let input = io.input.unwrap_or_default();
        let mut block = Zeroizing::new([0u8; 64]);
        self.chacha.counter &= !0xffff_ffff;
        sym::chacha20_blocks(
            &self.chacha.key,
            self.chacha.nonce,
            self.chacha.counter,
            &mut block[..],
        )
        .map_err(|_| Error::Internal)?;
        self.poly = Some(Hash(
            sym::universal_hash(HashAlgorithm::Poly1305, block.get(..32).unwrap_or_default())
                .map_err(|_| Error::Internal)?,
        ));
        self.pend.clear();
        self.chacha.partial = 0;
        self.len_aad = TLS1_AAD_LEN as u64;
        self.len_text = u64::try_from(plen).unwrap_or(0);
        let aad = *self.tls_aad;
        self.poly_update(&aad[..16]);
        let mut d = input.get(..plen).unwrap_or_default().to_vec();
        // The payload's key stream from block 1, as ChaCha20_ctr32 there.
        let mut ks = ChaCha {
            key: self.chacha.key.clone(),
            counter: (self.chacha.counter & !0xffff_ffff) | 1,
            nonce: self.chacha.nonce,
            stream: Zeroizing::new([0; 64]),
            partial: 0,
        };
        if self.enc {
            ks.apply(&mut d)?;
            self.poly_update(&d);
        } else {
            self.poly_update(&d.clone());
            ks.apply(&mut d)?;
        }
        self.poly_pad(self.len_text);
        let l = self.lengths();
        self.poly_update(&l);
        let t = self.poly_final();
        self.tls_payload_length = None;
        if plen > 64 {
            self.chacha.counter |= 1;
        }
        if self.enc {
            *self.tag = t;
            d.extend_from_slice(&t);
            let len = io.inl;
            return Ok(Output::new(d, len));
        }
        let ok = input
            .get(plen..plen.saturating_add(TAG_LEN))
            .is_some_and(|x| ct_eq(&t, x));
        if !ok {
            d.as_mut_slice().zeroize();
            let mut o = Output::new(d, 0);
            o.failed = Some(Error::Silent);
            return Ok(o);
        }
        Ok(Output::new(d, io.inl.saturating_sub(TAG_LEN)))
    }

    /// `chacha20_poly1305_update`: nothing for no input.
    pub fn update(&mut self, io: Io<'_>) -> Result<Output, Error> {
        crate::dit::with(|| self.update_dit(io))
    }

    /// [`Self::update`]'s work.
    fn update_dit(&mut self, io: Io<'_>) -> Result<Output, Error> {
        if io.inl == 0 {
            return Ok(Output::new(Vec::new(), 0));
        }
        self.cipher(io)
    }

    /// `chacha20_poly1305_cipher`.
    pub fn cipher(&mut self, io: Io<'_>) -> Result<Output, Error> {
        crate::dit::with(|| self.cipher_dit(io))
    }

    /// [`Self::cipher`]'s work.
    fn cipher_dit(&mut self, io: Io<'_>) -> Result<Output, Error> {
        if io.outsize < io.inl {
            return Err(Error::OutputBufferTooSmall);
        }
        self.aead(io)
    }

    /// `chacha20_poly1305_final`.
    pub fn finalize(&mut self) -> Result<Output, Error> {
        crate::dit::with(|| self.finalize_dit())
    }

    /// [`Self::finalize`]'s work.
    fn finalize_dit(&mut self) -> Result<Output, Error> {
        let io = Io {
            input: None,
            inl: 0,
            out: true,
            in_place: false,
            outsize: 0,
        };
        let o = self.aead(io)?;
        if o.failed.is_some() {
            return Err(Error::Silent);
        }
        Ok(Output::new(Vec::new(), 0))
    }
}

impl Default for ChaChaPoly {
    fn default() -> Self {
        Self::new()
    }
}
