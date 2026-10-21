//! XTS and the key wraps on the generic context: `cipher_aes_xts.c` and `cipher_sm4_xts.c`
//! over `xts128.c` and `xts128gb.c`, `cipher_aes_wrp.c` over `wrap128.c`, and
//! `cipher_tdes_wrap.c`.
//!
//! Each keeps the transformation its key schedule was made for when the key was set, as the
//! reference's do: an XTS or key-wrap context initialized in the other direction without a new
//! key still runs the old direction's cipher (AES-XTS its whole operation, SM4-XTS and the
//! wraps their block cipher).
//!
//! Without a key, the key wraps fail here; the reference runs its cipher on a key schedule
//! never set (docs/DEVIATIONS.md).

use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

use super::{Ctx, Error, Generic, Kind, Mode, Output, add, cbc, sub};
use crate::provided::aead::{Io, Raised};
use crate::sym::{self, BlockAlgorithm, BlockCipher};

/// `XTS_MAX_BLOCKS_PER_DATA_UNIT`: IEEE Std 1619-2018's limit, in 16-octet blocks.
const XTS_MAX_BLOCKS: usize = 1 << 20;
/// `wrap128.c`'s default IV.
const DEFAULT_IV: [u8; 8] = [0xa6; 8];
/// RFC 5649's alternative initial value.
const DEFAULT_AIV: [u8; 4] = [0xa6, 0x59, 0x59, 0xa6];
/// `CRYPTO128_WRAP_MAX`.
const WRAP_MAX: usize = 1 << 31;
/// `cipher_tdes_wrap.c`'s `wrap_iv` (RFC 3217).
const TDES_WRAP_IV: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];
/// `EVP_MAXCHUNK`.
const MAX_CHUNK: usize = 1 << 30;

impl Ctx {
    /// `update` (`one_shot` false) or `cipher` for XTS and the key wraps; `None` for the other
    /// modes, which take [`Ctx::update`] and [`Ctx::cipher`].
    pub fn process(&mut self, io: Io<'_>, one_shot: bool) -> Option<Result<Output, Raised>> {
        let Self::Generic(g) = self else {
            return None;
        };
        let kind = g.kind;
        if kind.xts() {
            return Some(g.xts_process(io, one_shot));
        }
        if kind.composite() {
            return Some(g.composite_process(io, one_shot).map_err(Raised::from));
        }
        if kind.etm() {
            return Some(g.etm_process(io, one_shot));
        }
        if !kind.wrap() {
            return None;
        }
        if matches!(
            kind,
            Kind::Block {
                algorithm: BlockAlgorithm::TripleDes,
                ..
            }
        ) {
            return Some(g.tdes_wrap_process(io, one_shot));
        }
        Some(g.wrap_process(io).map_err(Raised::from))
    }

    /// `final` for XTS and the key wraps: nothing (triple DES's needs a key); `None` for the
    /// other modes.
    pub fn process_final(&mut self) -> Option<Result<Output, Error>> {
        let Self::Generic(g) = self else {
            return None;
        };
        let kind = g.kind;
        if !kind.xts() && !kind.wrap() && !kind.composite() {
            return None;
        }
        if (kind.has_rand_key() || kind.composite()) && !g.key_set {
            return Some(Err(Error::NoKeySet));
        }
        Some(Ok(Output::new(Vec::new(), 0)))
    }
}

/// The input of a call, or a silent failure for a NULL pointer.
fn need<'a>(io: &Io<'a>) -> Result<&'a [u8], Error> {
    let input = io.input.ok_or(Error::Silent)?;
    input.get(..io.inl).ok_or(Error::Silent)
}

/// Constant-time equality of two octet strings of one length.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// SHA-1 of `data`.
fn sha1(data: &[u8]) -> Zeroizing<[u8; 20]> {
    Zeroizing::new(Sha1::digest(data).into())
}

/// An inner failure, then the function's own error.
fn wrap_err(first: Error, outer: Error) -> Raised {
    Raised {
        first,
        then: Some(outer),
    }
}

impl Generic {
    /// The composites' `update` (`ossl_cipher_generic_stream_update`) and `cipher`
    /// (`ossl_cipher_generic_cipher`).
    fn composite_process(&mut self, io: Io<'_>, one_shot: bool) -> Result<Output, Error> {
        if !self.key_set {
            return Err(Error::NoKeySet);
        }
        if !one_shot && io.inl == 0 {
            return Ok(Output::new(Vec::new(), 0));
        }
        if io.outsize < io.inl {
            return Err(Error::OutputBufferTooSmall);
        }
        let input = need(&io).map_err(|_| Error::CipherOperationFailed)?;
        let mut out = self.composite_cipher(input)?;
        if !one_shot {
            self.composite_tls_unpad(&mut out)?;
        }
        Ok(out)
    }

    // ---------------------------------------------------------------------------------------
    // XTS

    /// `aes_xts_init`/`sm4_xts_init` before the parameters.
    pub(super) fn xts_init(
        &mut self,
        enc: bool,
        key: Option<&[u8]>,
        iv: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.enc = enc;
        if let Some(iv) = iv {
            self.init_iv(iv)?;
        }
        if let Some(key) = key {
            if key.len() != self.keylen {
                return Err(Error::InvalidKeyLength);
            }
            let half = self.keylen / 2;
            let (k1, k2) = key.split_at(half);
            let algorithm = self.algorithm();
            // AES-XTS refuses two equal keys to encrypt (FIPS 140's IG C.I); decrypting is
            // allowed outside the FIPS provider.
            if algorithm == BlockAlgorithm::Aes && enc && ct_eq(k1, k2) {
                return Err(Error::XtsDuplicatedKeys);
            }
            let c1 =
                sym::block_cipher(algorithm, k1, None).map_err(|_| Error::CipherOperationFailed)?;
            let c2 =
                sym::block_cipher(algorithm, k2, None).map_err(|_| Error::CipherOperationFailed)?;
            self.cipher = Some(c1);
            self.cipher2 = Some(c2);
            self.key_enc = enc;
        }
        Ok(())
    }

    /// The block cipher of a block mode.
    fn algorithm(&self) -> BlockAlgorithm {
        match self.kind {
            Kind::Block { algorithm, .. } => algorithm,
            _ => BlockAlgorithm::Aes,
        }
    }

    /// `aes_xts_stream_update` and `aes_xts_cipher` (SM4's likewise).
    fn xts_process(&mut self, io: Io<'_>, one_shot: bool) -> Result<Output, Raised> {
        if !one_shot && io.outsize < io.inl {
            return Err(Error::OutputBufferTooSmall.into());
        }
        self.xts_cipher(&io).map_err(|e| {
            if one_shot {
                Raised::from(e)
            } else {
                wrap_err(e, Error::CipherOperationFailed)
            }
        })
    }

    /// `aes_xts_cipher`: one data unit of at least a block and at most 2^20 blocks.
    fn xts_cipher(&self, io: &Io<'_>) -> Result<Output, Error> {
        let (Some(k1), Some(k2)) = (self.cipher.as_ref(), self.cipher2.as_ref()) else {
            return Err(Error::Silent);
        };
        if !self.iv_set || !io.out || io.inl < 16 {
            return Err(Error::Silent);
        }
        let input = need(io)?;
        if io.inl > XTS_MAX_BLOCKS * 16 {
            return Err(Error::XtsDataUnitIsTooLarge);
        }
        // AES's assembly runs the whole operation the key was set for; SM4's takes the
        // direction from the context and only its block cipher from the key.
        let flow = if self.algorithm() == BlockAlgorithm::Aes {
            self.key_enc
        } else {
            self.enc
        };
        let tweak: [u8; 16] = self
            .iv
            .get(..16)
            .and_then(|v| v.try_into().ok())
            .ok_or(Error::Internal)?;
        let data = xts(
            k1.as_ref(),
            k2.as_ref(),
            self.key_enc,
            tweak,
            input,
            flow,
            self.xts_ieee,
        )?;
        let len = data.len();
        Ok(Output::new(data, len))
    }

    /// SM4-XTS's standard (`xts_standard`): IEEE 1619 or GB/T 17964-2021.
    pub fn set_xts_ieee(&mut self, ieee: bool) {
        self.xts_ieee = ieee;
    }

    // ---------------------------------------------------------------------------------------
    // The AES key wraps

    /// `aes_wrap_init` before the parameters.
    pub(super) fn wrap_init(
        &mut self,
        enc: bool,
        key: Option<&[u8]>,
        iv: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.enc = enc;
        if let Some(iv) = iv {
            self.init_iv(iv)?;
        }
        if let Some(key) = key {
            if key.len() != self.keylen {
                return Err(Error::InvalidKeyLength);
            }
            let c = sym::block_cipher(self.algorithm(), key, None)
                .map_err(|_| Error::CipherOperationFailed)?;
            self.cipher = Some(c);
            // SP 800-38F 5.1: the -INV variants' forward transformation is the inverse cipher.
            self.key_enc = enc != self.kind.inverse_cipher();
        }
        Ok(())
    }

    /// `aes_wrap_cipher` (the update; the AES key wraps have no `cipher`). A failure inside
    /// is reported, as the reference's is, as success with a length of `SIZE_MAX` and the
    /// error raised; `EVP_CipherUpdate` then fails.
    fn wrap_process(&mut self, io: Io<'_>) -> Result<Output, Error> {
        if io.inl == 0 {
            return Ok(Output::new(Vec::new(), 0));
        }
        if io.outsize < io.inl {
            return Err(Error::OutputBufferTooSmall);
        }
        let Some(input) = io.input else {
            return Err(Error::Silent);
        };
        let input = input.get(..io.inl).ok_or(Error::Silent)?;
        let failed = |data: Vec<u8>, e: Error| {
            let mut o = Output::new(data, usize::MAX);
            o.raised = Some(e);
            Ok(o)
        };
        let pad = matches!(
            self.kind,
            Kind::Block {
                mode: Mode::WrapPad | Mode::WrapPadInv,
                ..
            }
        );
        let inl = io.inl;
        let whole = inl.is_multiple_of(8);
        if (!self.enc && (inl < 16 || !whole)) || (!pad && !whole) {
            return failed(Vec::new(), Error::InvalidInputLength);
        }
        if !io.out {
            let len = if self.enc {
                let n = if pad {
                    inl.div_ceil(8).saturating_mul(8)
                } else {
                    inl
                };
                n.saturating_add(8)
            } else {
                inl.saturating_sub(8)
            };
            return Ok(Output::new(Vec::new(), len));
        }
        let Some(cipher) = self.cipher.as_ref() else {
            // The reference wraps with a key schedule never set (docs/DEVIATIONS.md).
            return failed(Vec::new(), Error::CipherOperationFailed);
        };
        let block = Block {
            cipher: cipher.as_ref(),
            forward: self.key_enc,
        };
        let ivlen = self.ivlen;
        let iv = if self.iv_set {
            self.iv.get(..ivlen)
        } else {
            None
        };
        let result = match (self.enc, pad) {
            (true, false) => wrap(&block, iv, input),
            (false, false) => unwrap(&block, iv, input),
            (true, true) => wrap_pad(&block, iv, input),
            (false, true) => unwrap_pad(&block, iv, input),
        };
        match result {
            Ok(data) if data.len() > usize::try_from(i32::MAX).unwrap_or(usize::MAX) => {
                failed(Vec::new(), Error::InvalidOutputLength)
            }
            Ok(data) => {
                let len = data.len();
                Ok(Output::new(data, len))
            }
            Err(wiped) => failed(wiped, Error::CipherOperationFailed),
        }
    }

    // ---------------------------------------------------------------------------------------
    // Triple DES's key wrap

    /// `tdes_wrap_update` (`one_shot` false) and `tdes_wrap_cipher`.
    fn tdes_wrap_process(&mut self, io: Io<'_>, one_shot: bool) -> Result<Output, Raised> {
        if !one_shot && io.inl == 0 {
            return Ok(Output::new(Vec::new(), 0));
        }
        if io.outsize < io.inl {
            return Err(Error::OutputBufferTooSmall.into());
        }
        let r = self.tdes_wrap_internal(&io);
        match r {
            Ok(o) if o.failed.is_none() => Ok(o),
            Ok(mut o) if !one_shot => {
                o.failed = Some(Error::CipherOperationFailed);
                Ok(o)
            }
            Ok(o) => Ok(o),
            Err(e) if one_shot => Err(e.into()),
            Err(e) => Err(wrap_err(e, Error::CipherOperationFailed)),
        }
    }

    /// `tdes_wrap_cipher_internal`.
    fn tdes_wrap_internal(&mut self, io: &Io<'_>) -> Result<Output, Error> {
        let inl = io.inl;
        if inl >= MAX_CHUNK || !inl.is_multiple_of(8) {
            return Err(Error::Silent);
        }
        if self.enc {
            if !io.out {
                return Ok(Output::new(Vec::new(), add(inl, 16)?));
            }
            let input = need(io)?;
            self.des_ede3_wrap(input)
        } else {
            if inl < 24 {
                return Err(Error::Silent);
            }
            if !io.out {
                return Ok(Output::new(Vec::new(), sub(inl, 16)?));
            }
            let input = need(io)?;
            self.des_ede3_unwrap(input)
        }
    }

    /// Triple-DES CBC in place from the running IV, in the context's direction.
    fn tdes_cbc(&mut self, data: &mut [u8]) -> Result<(), Error> {
        let cipher = self.cipher.as_ref().ok_or(Error::Silent)?;
        let iv = self.iv.get_mut(..8).ok_or(Error::Internal)?;
        cbc(cipher.as_ref(), iv, data, self.enc).map_err(|_| Error::Silent)
    }

    /// `des_ede3_wrap`: the key and its SHA-1 check value, CBC-encrypted under a random IV,
    /// reversed, and encrypted again under RFC 3217's IV.
    fn des_ede3_wrap(&mut self, input: &[u8]) -> Result<Output, Error> {
        if self.cipher.is_none() {
            // The reference wraps with a key schedule never set (docs/DEVIATIONS.md).
            return Err(Error::Silent);
        }
        let inl = input.len();
        let len = add(inl, 16)?;
        let mut out = Zeroizing::new(vec![0u8; len]);
        let end = add(8, inl)?;
        out.get_mut(8..end)
            .ok_or(Error::Internal)?
            .copy_from_slice(input);
        let digest = sha1(input);
        out.get_mut(end..len)
            .ok_or(Error::Internal)?
            .copy_from_slice(digest.get(..8).ok_or(Error::Internal)?);
        let mut iv = [0u8; 8];
        if !crate::rand::fill(self.rng.as_ref(), &mut iv) {
            return Err(Error::Silent);
        }
        self.iv
            .get_mut(..8)
            .ok_or(Error::Internal)?
            .copy_from_slice(&iv);
        out.get_mut(..8)
            .ok_or(Error::Internal)?
            .copy_from_slice(&iv);
        self.tdes_cbc(out.get_mut(8..).ok_or(Error::Internal)?)?;
        out.reverse();
        self.iv
            .get_mut(..8)
            .ok_or(Error::Internal)?
            .copy_from_slice(&TDES_WRAP_IV);
        self.tdes_cbc(&mut out)?;
        Ok(Output::new(out.to_vec(), len))
    }

    /// `des_ede3_unwrap`: the reverse; a check value that doesn't match wipes the output.
    fn des_ede3_unwrap(&mut self, input: &[u8]) -> Result<Output, Error> {
        if self.cipher.is_none() {
            // As for wrapping (docs/DEVIATIONS.md).
            return Err(Error::Silent);
        }
        let inl = input.len();
        let n = sub(inl, 16)?;
        self.iv
            .get_mut(..8)
            .ok_or(Error::Internal)?
            .copy_from_slice(&TDES_WRAP_IV);
        let mut icv = Zeroizing::new([0u8; 8]);
        icv.copy_from_slice(input.get(..8).ok_or(Error::Internal)?);
        self.tdes_cbc(icv.as_mut_slice())?;
        let mut out = Zeroizing::new(input.get(8..add(8, n)?).ok_or(Error::Internal)?.to_vec());
        self.tdes_cbc(&mut out)?;
        let mut iv = Zeroizing::new([0u8; 8]);
        iv.copy_from_slice(input.get(sub(inl, 8)?..).ok_or(Error::Internal)?);
        self.tdes_cbc(iv.as_mut_slice())?;
        icv.reverse();
        out.reverse();
        iv.reverse();
        self.iv
            .get_mut(..8)
            .ok_or(Error::Internal)?
            .copy_from_slice(iv.as_slice());
        self.tdes_cbc(&mut out)?;
        self.tdes_cbc(icv.as_mut_slice())?;
        let digest = sha1(&out);
        let ok = ct_eq(digest.get(..8).ok_or(Error::Internal)?, icv.as_slice());
        self.iv.fill(0);
        let mut o = Output::new(out.to_vec(), n);
        if !ok {
            o.data.as_mut_slice().fill(0);
            o.failed = Some(Error::Silent);
        }
        Ok(o)
    }
}

/// The wraps' block function: the cipher in the direction chosen when the key was set.
struct Block<'a> {
    cipher: &'a dyn BlockCipher,
    forward: bool,
}

impl Block<'_> {
    fn apply(&self, b: &mut [u8; 16]) -> Result<(), Vec<u8>> {
        let r = if self.forward {
            self.cipher.encrypt_blocks(b)
        } else {
            self.cipher.decrypt_blocks(b)
        };
        r.map_err(|_| Vec::new())
    }
}

/// XORs the step counter `t` into A as `wrap128.c` does (its low 32 bits, big-endian).
fn xor_t(a: &mut [u8; 16], t: usize) {
    let t = u32::try_from(t & 0xffff_ffff).unwrap_or(0).to_be_bytes();
    for (x, y) in a.get_mut(4..8).unwrap_or_default().iter_mut().zip(t) {
        *x ^= y;
    }
}

/// Whether `len` is a key length the wraps take: a multiple of 8 from 16 to 2^31.
fn wrappable(len: usize) -> bool {
    len.is_multiple_of(8) && (16..=WRAP_MAX).contains(&len)
}

/// `CRYPTO_128_wrap`: `Err` (nothing written) for a length that isn't a multiple of 8 from 16
/// to 2^31.
fn wrap(block: &Block<'_>, iv: Option<&[u8]>, input: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
    if !wrappable(input.len()) {
        return Err(Vec::new());
    }
    let mut out = vec![0u8; input.len().saturating_add(8)];
    out.get_mut(8..).unwrap_or_default().copy_from_slice(input);
    let mut b = Zeroizing::new([0u8; 16]);
    let iv = iv.and_then(|v| v.get(..8)).unwrap_or(&DEFAULT_IV);
    b.get_mut(..8).unwrap_or_default().copy_from_slice(iv);
    let mut t = 1usize;
    for _ in 0..6 {
        for r in out.get_mut(8..).unwrap_or_default().as_chunks_mut::<8>().0 {
            b.get_mut(8..).unwrap_or_default().copy_from_slice(r);
            block.apply(&mut b)?;
            xor_t(&mut b, t);
            r.copy_from_slice(b.get(8..).unwrap_or_default());
            t = t.wrapping_add(1);
        }
    }
    out.get_mut(..8)
        .unwrap_or_default()
        .copy_from_slice(b.get(..8).unwrap_or_default());
    Ok(out)
}

/// `crypto_128_unwrap_raw`: the key data and the recovered IV; `None` for a bad length.
fn unwrap_raw(block: &Block<'_>, input: &[u8]) -> Option<(Vec<u8>, [u8; 8])> {
    let inlen = input.len().checked_sub(8)?;
    if !wrappable(inlen) {
        return None;
    }
    let mut b = Zeroizing::new([0u8; 16]);
    b.get_mut(..8)?.copy_from_slice(input.get(..8)?);
    let mut out = input.get(8..)?.to_vec();
    let mut t = (inlen >> 3).checked_mul(6)?;
    for _ in 0..6 {
        for r in out.as_chunks_mut::<8>().0.iter_mut().rev() {
            xor_t(&mut b, t);
            b.get_mut(8..)?.copy_from_slice(r);
            block.apply(&mut b).ok()?;
            r.copy_from_slice(b.get(8..)?);
            t = t.wrapping_sub(1);
        }
    }
    let a: [u8; 8] = b.get(..8)?.try_into().ok()?;
    Some((out, a))
}

/// `CRYPTO_128_unwrap`: `Err` with what's left at the output (zeros) when it fails.
fn unwrap(block: &Block<'_>, iv: Option<&[u8]>, input: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
    let Some((out, got)) = unwrap_raw(block, input) else {
        return Err(Vec::new());
    };
    let iv = iv.and_then(|v| v.get(..8)).unwrap_or(&DEFAULT_IV);
    if !ct_eq(&got, iv) {
        return Err(vec![0; out.len()]);
    }
    Ok(out)
}

/// `CRYPTO_128_wrap_pad`.
fn wrap_pad(block: &Block<'_>, icv: Option<&[u8]>, input: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
    let inlen = input.len();
    if !(1..WRAP_MAX).contains(&inlen) {
        return Err(Vec::new());
    }
    let padded = inlen.div_ceil(8).saturating_mul(8);
    let mut aiv = [0u8; 8];
    let head = icv.and_then(|v| v.get(..4)).unwrap_or(&DEFAULT_AIV);
    aiv.get_mut(..4).unwrap_or_default().copy_from_slice(head);
    let n = u32::try_from(inlen).map_err(|_| Vec::new())?.to_be_bytes();
    aiv.get_mut(4..).unwrap_or_default().copy_from_slice(&n);
    if padded == 8 {
        let mut b = Zeroizing::new([0u8; 16]);
        b.get_mut(..8).unwrap_or_default().copy_from_slice(&aiv);
        b.get_mut(8..)
            .unwrap_or_default()
            .iter_mut()
            .zip(input)
            .for_each(|(d, s)| *d = *s);
        block.apply(&mut b)?;
        return Ok(b.to_vec());
    }
    let mut data = Zeroizing::new(vec![0u8; padded]);
    data.iter_mut().zip(input).for_each(|(d, s)| *d = *s);
    wrap(block, Some(&aiv), &data)
}

/// `CRYPTO_128_unwrap_pad`: `Err` with zeros over the whole input's length when it fails.
fn unwrap_pad(block: &Block<'_>, icv: Option<&[u8]>, input: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
    let inlen = input.len();
    if !inlen.is_multiple_of(8) || !(16..WRAP_MAX).contains(&inlen) {
        return Err(Vec::new());
    }
    let n = (inlen / 8).saturating_sub(1);
    let wiped = || vec![0u8; inlen];
    let (out, aiv) = if inlen == 16 {
        let mut b = Zeroizing::new([0u8; 16]);
        b.copy_from_slice(input);
        block.apply(&mut b).map_err(|_| wiped())?;
        let aiv: [u8; 8] = b
            .get(..8)
            .and_then(|v| v.try_into().ok())
            .ok_or_else(wiped)?;
        (b.get(8..).unwrap_or_default().to_vec(), aiv)
    } else {
        unwrap_raw(block, input).ok_or_else(wiped)?
    };
    let out = Zeroizing::new(out);
    let head = icv.and_then(|v| v.get(..4)).unwrap_or(&DEFAULT_AIV);
    if !ct_eq(aiv.get(..4).unwrap_or_default(), head) {
        return Err(wiped());
    }
    let len_bytes: [u8; 4] = aiv
        .get(4..)
        .and_then(|v| v.try_into().ok())
        .ok_or_else(wiped)?;
    let ptext_len = usize::try_from(u32::from_be_bytes(len_bytes)).map_err(|_| wiped())?;
    // RFC 5649 4.2: 8(n-1) < ptext_len <= 8n.
    let low = n.saturating_sub(1).saturating_mul(8);
    if ptext_len <= low || ptext_len > n.saturating_mul(8) {
        return Err(wiped());
    }
    let padding = out.get(ptext_len..).ok_or_else(wiped)?;
    if padding.iter().fold(0u8, |a, b| a | b) != 0 {
        return Err(wiped());
    }
    Ok(out.get(..ptext_len).unwrap_or_default().to_vec())
}

/// The XTS tweak times x: IEEE 1619's little-endian doubling, or GB/T 17964's big-endian
/// halving.
fn next_tweak(t: &mut [u8; 16], ieee: bool) {
    if ieee {
        let mut carry = 0u8;
        for b in t.iter_mut() {
            let c = *b >> 7;
            *b = (*b << 1) | carry;
            carry = c;
        }
        if let Some(b) = t.first_mut() {
            *b ^= 0x87 & 0u8.wrapping_sub(carry);
        }
    } else {
        let mut carry = 0u8;
        for b in t.iter_mut() {
            let c = *b & 1;
            *b = (*b >> 1) | (carry << 7);
            carry = c;
        }
        if let Some(b) = t.first_mut() {
            *b ^= 0xe1 & 0u8.wrapping_sub(carry);
        }
    }
}

/// One block of XTS: `b` XOR the tweak through the cipher, XOR the tweak.
fn xts_block(
    k1: &dyn BlockCipher,
    forward: bool,
    b: &mut [u8; 16],
    t: &[u8; 16],
) -> Result<(), Error> {
    for (x, y) in b.iter_mut().zip(t) {
        *x ^= y;
    }
    let r = if forward {
        k1.encrypt_blocks(b)
    } else {
        k1.decrypt_blocks(b)
    };
    r.map_err(|_| Error::CipherOperationFailed)?;
    for (x, y) in b.iter_mut().zip(t) {
        *x ^= y;
    }
    Ok(())
}

/// Ciphertext stealing: the first `len` octets of `scratch` go to `out`, the input's take
/// their place.
fn steal(scratch: &mut [u8; 16], input: &[u8], out: &mut [u8], len: usize) -> Result<(), Error> {
    let s = scratch.get_mut(..len).ok_or(Error::Internal)?;
    let i = input.get(..len).ok_or(Error::Internal)?;
    out.get_mut(..len)
        .ok_or(Error::Internal)?
        .copy_from_slice(s);
    s.copy_from_slice(i);
    Ok(())
}

/// `CRYPTO_xts128_encrypt` (`ossl_crypto_xts128gb_encrypt` for GB/T): `input` (at least a
/// block) with the tweak `iv`, ciphertext stealing for a partial last block. The block cipher
/// runs in the direction `forward`; the stealing follows `enc`.
fn xts(
    k1: &dyn BlockCipher,
    k2: &dyn BlockCipher,
    forward: bool,
    iv: [u8; 16],
    input: &[u8],
    enc: bool,
    ieee: bool,
) -> Result<Vec<u8>, Error> {
    let mut tweak = Zeroizing::new(iv);
    k2.encrypt_blocks(tweak.as_mut_slice())
        .map_err(|_| Error::CipherOperationFailed)?;
    let total = input.len();
    let mut len = total;
    if !enc && !total.is_multiple_of(16) {
        len = sub(len, 16)?;
    }
    let mut out = vec![0u8; total];
    let mut scratch = Zeroizing::new([0u8; 16]);
    let mut pos = 0usize;
    while len >= 16 {
        let end = add(pos, 16)?;
        scratch.copy_from_slice(input.get(pos..end).ok_or(Error::Internal)?);
        xts_block(k1, forward, &mut scratch, &tweak)?;
        out.get_mut(pos..end)
            .ok_or(Error::Internal)?
            .copy_from_slice(scratch.as_slice());
        pos = end;
        len = sub(len, 16)?;
        if len == 0 {
            return Ok(out);
        }
        next_tweak(&mut tweak, ieee);
    }
    if enc {
        // `len` octets left: they take the start of the last whole block's ciphertext, which
        // is then re-encrypted with them in its place.
        steal(
            &mut scratch,
            input.get(pos..).ok_or(Error::Internal)?,
            out.get_mut(pos..).ok_or(Error::Internal)?,
            len,
        )?;
        xts_block(k1, forward, &mut scratch, &tweak)?;
        let prev = pos.checked_sub(16).ok_or(Error::Internal)?;
        out.get_mut(prev..pos)
            .ok_or(Error::Internal)?
            .copy_from_slice(scratch.as_slice());
    } else {
        let mut tweak1 = Zeroizing::new(*tweak);
        next_tweak(&mut tweak1, ieee);
        let end = add(pos, 16)?;
        scratch.copy_from_slice(input.get(pos..end).ok_or(Error::Internal)?);
        xts_block(k1, forward, &mut scratch, &tweak1)?;
        steal(
            &mut scratch,
            input.get(end..).ok_or(Error::Internal)?,
            out.get_mut(end..).ok_or(Error::Internal)?,
            len,
        )?;
        xts_block(k1, forward, &mut scratch, &tweak)?;
        out.get_mut(pos..end)
            .ok_or(Error::Internal)?
            .copy_from_slice(scratch.as_slice());
    }
    Ok(out)
}
