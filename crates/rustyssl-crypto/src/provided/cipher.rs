//! The default provider's ciphers with the semantics of their provider functions
//! (`providers/implementations/ciphers/`): what `einit`/`dinit`, `update`, `final`, `cipher`,
//! and the context parameters do to a context, which the EVP layer drives through the
//! provider's dispatch table.
//!
//! - **The block and stream modes** (`ciphercommon.c`, `ciphercommon_hw.c`, and the modes in
//!   `crypto/modes/`) over AES, ARIA, Camellia, SM4, and two- and three-key triple DES. ECB
//!   and CBC are block ciphers with OpenSSL's buffering: `update` holds a partial block, and
//!   when decrypting with padding it holds back the last whole block for `final`, which pads or
//!   checks and removes the padding. OFB, CFB, CFB8, CFB1, and CTR are stream ciphers (block
//!   size 1) whose partial-block position is the context's `num`. CFB1 counts bits instead of
//!   octets after `use-bits` is set.
//! - **ChaCha20** with OpenSSL's 16-octet IV: a 64-bit little-endian block counter and a 64-bit
//!   nonce, the partial block's key stream kept between calls.
//! - **The NULL cipher**, which copies, and drops a TLS MAC's length from what it decrypts.
//!
//! Each function returns what the provider would write and the length it would report, which
//! can differ: `cipher` (`EVP_Cipher`) on ECB and CBC leaves a trailing partial block unwritten
//! but reports it. Padding is checked in constant time (the reference returns as soon as one
//! byte is wrong), with the same results and errors.
//!
//! Two deviations (docs/DEVIATIONS.md): that partial block is the platform's in the reference
//! (its ARMv8 assembly encrypts the wrong block in ECB, its C CBC pads the block with the IV
//! and, decrypting, reads past the input); and TLS record padding (`tls-version`, which libssl
//! sets) is refused until the TLS step (Phase 7).

use zeroize::{Zeroize, Zeroizing};

use crate::sym::{self, BlockAlgorithm, BlockCipher};

/// The largest block (and IV) the generic context holds (`GENERIC_BLOCK_SIZE`).
const MAX_BLOCK: usize = 16;
/// ChaCha20's block.
const CHACHA_BLOCK: usize = 64;

/// The modes of the block ciphers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// ECB: a block cipher without an IV.
    Ecb,
    /// CBC.
    Cbc,
    /// OFB (64- or 128-bit feedback, the block's).
    Ofb,
    /// CFB with the block's feedback (CFB64 or CFB128).
    Cfb,
    /// CFB with 1-bit feedback.
    Cfb1,
    /// CFB with 8-bit feedback.
    Cfb8,
    /// CTR with a 128-bit big-endian counter.
    Ctr,
}

/// The default provider's ciphers handled here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A block cipher in a mode, with its key length in octets (16 or 24 for triple DES).
    Block {
        /// The block cipher.
        algorithm: BlockAlgorithm,
        /// The key length in octets.
        key_len: usize,
        /// The mode.
        mode: Mode,
    },
    /// ChaCha20.
    ChaCha20,
    /// The NULL cipher.
    Null,
}

impl Kind {
    /// The mode the cipher reports (`EVP_CIPH_*_MODE`; 0 for a stream cipher).
    pub const fn mode(self) -> u32 {
        match self {
            Self::Block { mode, .. } => match mode {
                Mode::Ecb => rustyssl_abi::EVP_CIPH_ECB_MODE.cast_unsigned(),
                Mode::Cbc => rustyssl_abi::EVP_CIPH_CBC_MODE.cast_unsigned(),
                Mode::Ofb => rustyssl_abi::EVP_CIPH_OFB_MODE.cast_unsigned(),
                Mode::Cfb | Mode::Cfb1 | Mode::Cfb8 => {
                    rustyssl_abi::EVP_CIPH_CFB_MODE.cast_unsigned()
                }
                Mode::Ctr => rustyssl_abi::EVP_CIPH_CTR_MODE.cast_unsigned(),
            },
            Self::ChaCha20 | Self::Null => 0,
        }
    }

    /// The key length in octets.
    pub const fn key_len(self) -> usize {
        match self {
            Self::Block { key_len, .. } => key_len,
            Self::ChaCha20 => 32,
            Self::Null => 0,
        }
    }

    /// The block size in octets: the cipher's for ECB and CBC, 1 for the stream modes.
    pub const fn block_size(self) -> usize {
        match self {
            Self::Block {
                algorithm,
                mode: Mode::Ecb | Mode::Cbc,
                ..
            } => algorithm.block_size(),
            _ => 1,
        }
    }

    /// The IV length in octets.
    pub const fn iv_len(self) -> usize {
        match self {
            Self::Block {
                mode: Mode::Ecb, ..
            }
            | Self::Null => 0,
            Self::Block { algorithm, .. } => algorithm.block_size(),
            Self::ChaCha20 => 16,
        }
    }

    /// Whether the cipher makes random keys (`has-randkey`; triple DES).
    pub const fn has_rand_key(self) -> bool {
        matches!(
            self,
            Self::Block {
                algorithm: BlockAlgorithm::TripleDes,
                ..
            }
        )
    }

    /// Whether the cipher handles its IV itself (`custom-iv`; ChaCha20).
    pub const fn custom_iv(self) -> bool {
        matches!(self, Self::ChaCha20)
    }
}

/// Why a provider function failed, for the error it raises (`ERR_LIB_PROV`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// No error is raised: the function returns 0.
    Silent,
    /// `PROV_R_NO_KEY_SET`.
    NoKeySet,
    /// `PROV_R_OUTPUT_BUFFER_TOO_SMALL`.
    OutputBufferTooSmall,
    /// `PROV_R_CIPHER_OPERATION_FAILED`.
    CipherOperationFailed,
    /// `PROV_R_WRONG_FINAL_BLOCK_LENGTH`.
    WrongFinalBlockLength,
    /// `PROV_R_BAD_DECRYPT`.
    BadDecrypt,
    /// `PROV_R_INVALID_KEY_LENGTH`.
    InvalidKeyLength,
    /// `PROV_R_INVALID_IV_LENGTH`.
    InvalidIvLength,
    /// `PROV_R_FAILED_TO_GET_PARAMETER`: a parameter of the wrong type or out of range.
    FailedToGetParameter,
    /// `PROV_R_FAILED_TO_GENERATE_KEY`.
    FailedToGenerateKey,
    /// `ERR_R_INTERNAL_ERROR`.
    Internal,
    /// `PROV_R_INVALID_TAG`.
    InvalidTag,
    /// `PROV_R_INVALID_TAG_LENGTH`.
    InvalidTagLength,
    /// `PROV_R_TAG_NOT_NEEDED`.
    TagNotNeeded,
    /// `PROV_R_TAG_NOT_SET`.
    TagNotSet,
    /// `PROV_R_TOO_MANY_RECORDS`.
    TooManyRecords,
    /// `PROV_R_INVALID_AAD`.
    InvalidAad,
    /// `PROV_R_INVALID_DATA`.
    InvalidData,
    /// `ERR_R_PASSED_INVALID_ARGUMENT`.
    PassedInvalidArgument,
    /// `PROV_R_FAILED_TO_SET_PARAMETER`.
    FailedToSetParameter,
}

/// What a function writes and reports.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Output {
    /// The octets to write at the output, from its start.
    pub data: Zeroizing<Vec<u8>>,
    /// The length reported (in bits for CFB1 counting bits).
    pub len: usize,
    /// The bits of the last octet of `data` to write, the rest keeping the output's (CFB1
    /// counting bits leaves the rest of a partial octet as it was); 0xff otherwise.
    pub last_mask: u8,
    /// Set when the function fails after writing `data` (an AEAD's decryption that doesn't
    /// authenticate wipes its output): the error to raise, or [`Error::Silent`].
    pub failed: Option<Error>,
}

impl Output {
    pub(crate) fn new(data: Vec<u8>, len: usize) -> Self {
        Self {
            data: Zeroizing::new(data),
            len,
            last_mask: 0xff,
            failed: None,
        }
    }
}

/// ChaCha20's state (`PROV_CHACHA20_CTX`): the key, the counter and nonce, and the rest of the
/// partial block's key stream.
#[derive(Clone)]
pub(crate) struct ChaCha {
    pub(crate) key: Zeroizing<[u8; 32]>,
    /// The 64-bit block counter (OpenSSL's first two counter words).
    pub(crate) counter: u64,
    /// The nonce (OpenSSL's last two counter words).
    pub(crate) nonce: [u8; 8],
    pub(crate) stream: Zeroizing<[u8; CHACHA_BLOCK]>,
    pub(crate) partial: usize,
}

impl ChaCha {
    /// A zero key, counter, and nonce (`OPENSSL_zalloc`).
    pub(crate) fn new() -> Self {
        Self {
            key: Zeroizing::new([0; 32]),
            counter: 0,
            nonce: [0; 8],
            stream: Zeroizing::new([0; CHACHA_BLOCK]),
            partial: 0,
        }
    }

    /// `chacha20_cipher`: the partial block's key stream, then whole blocks, then a new
    /// partial block.
    pub(crate) fn apply(&mut self, data: &mut [u8]) -> Result<(), Error> {
        let mut data = data;
        if self.partial > 0 {
            let take = CHACHA_BLOCK.saturating_sub(self.partial).min(data.len());
            let (head, rest) = data.split_at_mut(take);
            let end = self.partial.checked_add(take).ok_or(Error::Internal)?;
            for (b, k) in head
                .iter_mut()
                .zip(self.stream.get(self.partial..end).ok_or(Error::Internal)?)
            {
                *b ^= k;
            }
            self.partial = end;
            data = rest;
            if data.is_empty() {
                return Ok(());
            }
            if self.partial == CHACHA_BLOCK {
                self.partial = 0;
                self.counter = self.counter.wrapping_add(1);
            }
        }
        let whole = data.len() & !(CHACHA_BLOCK - 1);
        let (blocks, rest) = data.split_at_mut(whole);
        self.counter = sym::chacha20_blocks(&self.key, self.nonce, self.counter, blocks)
            .map_err(|_| Error::Internal)?;
        if !rest.is_empty() {
            self.stream.fill(0);
            sym::chacha20_blocks(
                &self.key,
                self.nonce,
                self.counter,
                self.stream.as_mut_slice(),
            )
            .map_err(|_| Error::Internal)?;
            for (b, k) in rest.iter_mut().zip(self.stream.iter()) {
                *b ^= k;
            }
            self.partial = rest.len();
        }
        Ok(())
    }
}

/// The generic cipher context (`PROV_CIPHER_CTX`), ChaCha20's included.
pub struct Generic {
    kind: Kind,
    /// The IV as set.
    oiv: [u8; MAX_BLOCK],
    /// The running IV (OFB's and CFB's key stream, CTR's counter).
    iv: [u8; MAX_BLOCK],
    /// A partial block (CTR's key stream).
    buf: Zeroizing<[u8; MAX_BLOCK]>,
    keylen: usize,
    ivlen: usize,
    blocksize: usize,
    bufsz: usize,
    pad: bool,
    enc: bool,
    iv_set: bool,
    key_set: bool,
    use_bits: bool,
    tlsmacsize: usize,
    num: u32,
    cipher: Option<Box<dyn BlockCipher>>,
    chacha: Option<ChaCha>,
}

impl Clone for Generic {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind,
            oiv: self.oiv,
            iv: self.iv,
            buf: self.buf.clone(),
            keylen: self.keylen,
            ivlen: self.ivlen,
            blocksize: self.blocksize,
            bufsz: self.bufsz,
            pad: self.pad,
            enc: self.enc,
            iv_set: self.iv_set,
            key_set: self.key_set,
            use_bits: self.use_bits,
            tlsmacsize: self.tlsmacsize,
            num: self.num,
            cipher: self.cipher.as_ref().map(|c| c.clone_box()),
            chacha: self.chacha.clone(),
        }
    }
}

impl Drop for Generic {
    fn drop(&mut self) {
        self.oiv.zeroize();
        self.iv.zeroize();
    }
}

/// The NULL cipher's context (`PROV_CIPHER_NULL_CTX`).
#[derive(Clone, Default)]
pub struct Null {
    enc: bool,
    tlsmacsize: usize,
}

/// An algorithm context.
#[derive(Clone)]
pub enum Ctx {
    /// The block and stream modes and ChaCha20.
    Generic(Box<Generic>),
    /// The NULL cipher.
    Null(Null),
}

impl Ctx {
    /// A new context (`newctx`): padding on, the cipher's key and IV lengths, no key.
    pub fn new(kind: Kind) -> Self {
        if kind == Kind::Null {
            return Self::Null(Null::default());
        }
        Self::Generic(Box::new(Generic {
            kind,
            oiv: [0; MAX_BLOCK],
            iv: [0; MAX_BLOCK],
            buf: Zeroizing::new([0; MAX_BLOCK]),
            keylen: kind.key_len(),
            ivlen: kind.iv_len(),
            blocksize: kind.block_size(),
            bufsz: 0,
            pad: true,
            enc: false,
            iv_set: false,
            key_set: false,
            use_bits: false,
            tlsmacsize: 0,
            num: 0,
            cipher: None,
            chacha: (kind == Kind::ChaCha20).then(ChaCha::new),
        }))
    }

    /// The cipher.
    pub fn kind(&self) -> Kind {
        match self {
            Self::Generic(g) => g.kind,
            Self::Null(_) => Kind::Null,
        }
    }

    /// `einit`/`dinit` before the parameters: the direction, then the IV and the key if given
    /// (each of the cipher's length). The parameters are set afterwards, by the caller.
    pub fn init(&mut self, enc: bool, key: Option<&[u8]>, iv: Option<&[u8]>) -> Result<(), Error> {
        match self {
            Self::Null(n) => {
                // The NULL cipher's `dinit` leaves the direction as it was.
                if enc {
                    n.enc = true;
                }
                Ok(())
            }
            Self::Generic(g) => g.init(enc, key, iv),
        }
    }

    /// `update`: up to `outsize` octets of output for `inl` octets (bits for CFB1 counting
    /// bits) of input; `input` holds [`Ctx::input_len`] of them.
    pub fn update(&mut self, input: &[u8], inl: usize, outsize: usize) -> Result<Output, Error> {
        match self {
            Self::Null(n) => n.cipher(input, outsize),
            Self::Generic(g) => {
                if g.is_block() {
                    g.block_update(input, outsize)
                } else {
                    g.stream_update(input, inl, outsize)
                }
            }
        }
    }

    /// `final`.
    pub fn finalize(&mut self, outsize: usize) -> Result<Output, Error> {
        match self {
            Self::Null(_) => Ok(Output::new(Vec::new(), 0)),
            Self::Generic(g) => {
                if g.is_block() {
                    g.block_final(outsize)
                } else if !g.key_set {
                    Err(Error::NoKeySet)
                } else {
                    Ok(Output::new(Vec::new(), 0))
                }
            }
        }
    }

    /// `cipher` (`EVP_Cipher`): the mode applied to `inl` octets (or bits) of input without
    /// buffering or padding.
    pub fn cipher(&mut self, input: &[u8], inl: usize, outsize: usize) -> Result<Output, Error> {
        match self {
            Self::Null(n) => n.cipher(input, outsize),
            Self::Generic(g) => g.cipher(input, inl, outsize),
        }
    }

    /// The length of the input `update` and `cipher` read for a length of `inl`: `inl` octets,
    /// or `inl` bits rounded up for CFB1 counting bits.
    pub fn input_len(&self, inl: usize) -> usize {
        match self {
            Self::Generic(g) if g.counts_bits() => inl.div_ceil(8),
            _ => inl,
        }
    }

    /// The generic context, for its parameters; `None` for the NULL cipher.
    pub fn generic(&self) -> Option<&Generic> {
        match self {
            Self::Generic(g) => Some(g),
            Self::Null(_) => None,
        }
    }

    /// The generic context, mutably.
    pub fn generic_mut(&mut self) -> Option<&mut Generic> {
        match self {
            Self::Generic(g) => Some(g),
            Self::Null(_) => None,
        }
    }

    /// The NULL cipher's TLS MAC length (`tls-mac-size`).
    pub fn null_mac_size(&self) -> Option<usize> {
        match self {
            Self::Null(n) => Some(n.tlsmacsize),
            Self::Generic(_) => None,
        }
    }

    /// Sets the NULL cipher's TLS MAC length.
    pub fn set_null_mac_size(&mut self, size: usize) {
        if let Self::Null(n) = self {
            n.tlsmacsize = size;
        }
    }

    /// Whether the NULL cipher is decrypting with a TLS MAC: its output then leaves out the
    /// input's last `tls-mac-size` octets, the MAC.
    pub fn null_strips_mac(&self) -> bool {
        matches!(self, Self::Null(n) if !n.enc && n.tlsmacsize > 0)
    }
}

impl Null {
    /// `null_cipher`: copies the input, less a TLS MAC when decrypting.
    fn cipher(&self, input: &[u8], outsize: usize) -> Result<Output, Error> {
        let mut inl = input.len();
        if !self.enc && self.tlsmacsize > 0 {
            inl = inl.checked_sub(self.tlsmacsize).ok_or(Error::Silent)?;
        }
        if outsize < inl {
            return Err(Error::Silent);
        }
        let data = input.get(..inl).ok_or(Error::Silent)?.to_vec();
        Ok(Output::new(data, inl))
    }
}

impl Generic {
    fn is_block(&self) -> bool {
        matches!(
            self.kind,
            Kind::Block {
                mode: Mode::Ecb | Mode::Cbc,
                ..
            }
        )
    }

    fn mode(&self) -> Option<Mode> {
        match self.kind {
            Kind::Block { mode, .. } => Some(mode),
            _ => None,
        }
    }

    fn is_tdes(&self) -> bool {
        self.kind.has_rand_key()
    }

    /// Whether lengths count bits (CFB1 after `use-bits`).
    fn counts_bits(&self) -> bool {
        self.use_bits && self.mode() == Some(Mode::Cfb1)
    }

    /// `cipher_generic_init_internal`, `tdes_init`, and ChaCha20's init, without the
    /// parameters.
    fn init(&mut self, enc: bool, key: Option<&[u8]>, iv: Option<&[u8]>) -> Result<(), Error> {
        self.num = 0;
        self.bufsz = 0;
        self.enc = enc;
        let mode = self.mode();
        if let Some(iv) = iv {
            if mode != Some(Mode::Ecb) || self.is_tdes() {
                self.init_iv(iv)?;
            }
        } else if self.iv_set
            && matches!(
                mode,
                Some(Mode::Cbc | Mode::Cfb | Mode::Cfb1 | Mode::Cfb8 | Mode::Ofb)
            )
        {
            // Back to the IV as set, as OpenSSL 1.1.1 did. (CFB1 and CFB8 are CFB to the
            // reference: their `ctx->mode` is EVP_CIPH_CFB_MODE too.)
            let n = self.ivlen.min(MAX_BLOCK);
            if let (Some(to), Some(from)) = (self.iv.get_mut(..n), self.oiv.get(..n)) {
                to.copy_from_slice(from);
            }
        }
        if let Some(key) = key {
            if key.len() != self.keylen {
                return Err(Error::InvalidKeyLength);
            }
            self.init_key(key)?;
            self.key_set = true;
        }
        if let (Some(_), Some(c)) = (iv, self.chacha.as_mut()) {
            // `chacha20_initiv`: the counter and nonce from the IV as set.
            let (counter, nonce) = self.oiv.split_at(8);
            let counter: [u8; 8] = counter.try_into().map_err(|_| Error::Internal)?;
            c.counter = u64::from_le_bytes(counter);
            c.nonce = nonce.try_into().map_err(|_| Error::Internal)?;
            c.partial = 0;
        }
        Ok(())
    }

    /// `ossl_cipher_generic_initiv`.
    fn init_iv(&mut self, iv: &[u8]) -> Result<(), Error> {
        if iv.len() != self.ivlen || iv.len() > MAX_BLOCK {
            return Err(Error::InvalidIvLength);
        }
        self.iv_set = true;
        if let (Some(a), Some(b)) = (self.iv.get_mut(..iv.len()), self.oiv.get_mut(..iv.len())) {
            a.copy_from_slice(iv);
            b.copy_from_slice(iv);
        }
        Ok(())
    }

    /// The key schedule (`hw->init`).
    fn init_key(&mut self, key: &[u8]) -> Result<(), Error> {
        match self.kind {
            Kind::Block { algorithm, .. } => {
                let c = sym::block_cipher(algorithm, key, None)
                    .map_err(|_| Error::CipherOperationFailed)?;
                self.cipher = Some(c);
            }
            Kind::ChaCha20 => {
                let c = self.chacha.as_mut().ok_or(Error::Internal)?;
                let k: &[u8; 32] = key.try_into().map_err(|_| Error::InvalidKeyLength)?;
                c.key.copy_from_slice(k);
                c.partial = 0;
            }
            Kind::Null => {}
        }
        Ok(())
    }

    /// `ossl_cipher_generic_block_update`.
    fn block_update(&mut self, input: &[u8], outsize: usize) -> Result<Output, Error> {
        if !self.key_set {
            return Err(Error::NoKeySet);
        }
        let blksz = self.blocksize;
        let mut input = input;
        let mut out: Vec<u8> = Vec::new();
        let mut nextblocks = if self.bufsz != 0 {
            // `ossl_cipher_fillblock`.
            let take = blksz.saturating_sub(self.bufsz).min(input.len());
            let (head, rest) = input.split_at(take);
            let end = self.bufsz.checked_add(take).ok_or(Error::Internal)?;
            self.buf
                .get_mut(self.bufsz..end)
                .ok_or(Error::Internal)?
                .copy_from_slice(head);
            self.bufsz = end;
            input = rest;
            input.len() & !(blksz.wrapping_sub(1))
        } else {
            input.len() & !(blksz.wrapping_sub(1))
        };
        // Decrypting with padding, a block that ends the input is held back for `final`.
        if self.bufsz == blksz && (self.enc || !input.is_empty() || !self.pad) {
            if outsize < blksz {
                return Err(Error::OutputBufferTooSmall);
            }
            let mut block = self.buf.get(..blksz).ok_or(Error::Internal)?.to_vec();
            self.hw(&mut block, blksz)?;
            out.append(&mut block);
            self.bufsz = 0;
        }
        if nextblocks > 0 {
            if !self.enc && self.pad && nextblocks == input.len() {
                nextblocks = nextblocks
                    .checked_sub(blksz)
                    .ok_or(Error::OutputBufferTooSmall)?;
            }
            let total = out.len().checked_add(nextblocks).ok_or(Error::Internal)?;
            if outsize < total {
                return Err(Error::OutputBufferTooSmall);
            }
        }
        if nextblocks > 0 {
            let (now, rest) = input.split_at(nextblocks);
            let mut blocks = now.to_vec();
            self.hw(&mut blocks, nextblocks)?;
            out.append(&mut blocks);
            input = rest;
        }
        if !input.is_empty() {
            // `ossl_cipher_trailingdata`.
            let end = self
                .bufsz
                .checked_add(input.len())
                .filter(|&e| e <= blksz)
                .ok_or(Error::Internal)?;
            self.buf
                .get_mut(self.bufsz..end)
                .ok_or(Error::Internal)?
                .copy_from_slice(input);
            self.bufsz = end;
        }
        let len = out.len();
        Ok(Output::new(out, len))
    }

    /// `ossl_cipher_generic_block_final`.
    fn block_final(&mut self, outsize: usize) -> Result<Output, Error> {
        if !self.key_set {
            return Err(Error::NoKeySet);
        }
        let blksz = self.blocksize;
        if self.enc {
            if self.pad {
                // `ossl_cipher_padblock`.
                let pad =
                    u8::try_from(blksz.saturating_sub(self.bufsz)).map_err(|_| Error::Internal)?;
                for b in self.buf.get_mut(self.bufsz..blksz).ok_or(Error::Internal)? {
                    *b = pad;
                }
                self.bufsz = blksz;
            } else if self.bufsz == 0 {
                return Ok(Output::new(Vec::new(), 0));
            } else if self.bufsz != blksz {
                return Err(Error::WrongFinalBlockLength);
            }
            if outsize < blksz {
                return Err(Error::OutputBufferTooSmall);
            }
            let mut block = self.buf.get(..blksz).ok_or(Error::Internal)?.to_vec();
            self.hw(&mut block, blksz)?;
            self.bufsz = 0;
            return Ok(Output::new(block, blksz));
        }
        if self.bufsz != blksz {
            if self.bufsz == 0 && !self.pad {
                return Ok(Output::new(Vec::new(), 0));
            }
            return Err(Error::WrongFinalBlockLength);
        }
        let mut block = self.buf.get(..blksz).ok_or(Error::Internal)?.to_vec();
        self.hw(&mut block, blksz)?;
        if let Some(b) = self.buf.get_mut(..blksz) {
            b.copy_from_slice(&block);
        }
        block.zeroize();
        if self.pad {
            self.bufsz = unpad(self.buf.get(..blksz).ok_or(Error::Internal)?)?;
        }
        if outsize < self.bufsz {
            return Err(Error::OutputBufferTooSmall);
        }
        let data = self.buf.get(..self.bufsz).ok_or(Error::Internal)?.to_vec();
        let len = data.len();
        self.bufsz = 0;
        Ok(Output::new(data, len))
    }

    /// `ossl_cipher_generic_stream_update` (without TLS record handling, which is refused).
    fn stream_update(&mut self, input: &[u8], inl: usize, outsize: usize) -> Result<Output, Error> {
        if !self.key_set {
            return Err(Error::NoKeySet);
        }
        if inl == 0 {
            return Ok(Output::new(Vec::new(), 0));
        }
        if outsize < inl {
            return Err(Error::OutputBufferTooSmall);
        }
        let mut data = input.to_vec();
        let mask = self.hw(&mut data, inl)?;
        let mut out = Output::new(data, inl);
        out.last_mask = mask;
        Ok(out)
    }

    /// `ossl_cipher_generic_cipher`.
    fn cipher(&mut self, input: &[u8], inl: usize, outsize: usize) -> Result<Output, Error> {
        if !self.key_set {
            return Err(Error::NoKeySet);
        }
        if outsize < inl {
            return Err(Error::OutputBufferTooSmall);
        }
        let mut data = input.to_vec();
        if self.is_block() {
            // Whole blocks only: a trailing partial block is left unwritten but counted
            // (docs/DEVIATIONS.md).
            let whole = inl & !(self.blocksize.wrapping_sub(1));
            data.truncate(whole);
            if whole > 0 {
                self.hw(&mut data, whole)?;
            }
            return Ok(Output::new(data, inl));
        }
        let mask = if inl > 0 {
            self.hw(&mut data, inl)?
        } else {
            0xff
        };
        let mut out = Output::new(data, inl);
        out.last_mask = mask;
        Ok(out)
    }

    /// The mode on `data` in place (`hw->cipher`), `len` octets (bits for CFB1 counting bits;
    /// for CFB1 counting octets, `data`'s length). Returns the mask of the last octet's bits
    /// it wrote.
    fn hw(&mut self, data: &mut [u8], len: usize) -> Result<u8, Error> {
        match self.kind {
            Kind::ChaCha20 => {
                self.chacha(data)?;
                Ok(0xff)
            }
            Kind::Null => Ok(0xff),
            Kind::Block { mode, .. } => {
                let bs = self.blocksize_of_cipher();
                let enc = self.enc;
                let cipher = self.cipher.as_ref().ok_or(Error::NoKeySet)?;
                let iv = self.iv.get_mut(..bs).ok_or(Error::Internal)?;
                match mode {
                    Mode::Ecb => {
                        let r = if enc {
                            cipher.encrypt_blocks(data)
                        } else {
                            cipher.decrypt_blocks(data)
                        };
                        r.map_err(|_| Error::CipherOperationFailed)?;
                    }
                    Mode::Cbc => cbc(cipher.as_ref(), iv, data, enc)?,
                    Mode::Ofb => self.num = ofb(cipher.as_ref(), iv, data, self.num)?,
                    Mode::Cfb => self.num = cfb(cipher.as_ref(), iv, data, self.num, enc)?,
                    Mode::Cfb8 => {
                        for b in data.iter_mut() {
                            *b = cfb_shift(cipher.as_ref(), iv, *b, 8, enc)?;
                        }
                    }
                    Mode::Cfb1 => {
                        let bits = if self.use_bits {
                            len
                        } else {
                            data.len().checked_mul(8).ok_or(Error::Internal)?
                        };
                        return cfb1(cipher.as_ref(), iv, data, bits, enc);
                    }
                    Mode::Ctr => {
                        let ks = self.buf.get_mut(..bs).ok_or(Error::Internal)?;
                        self.num = ctr(cipher.as_ref(), iv, ks, data, self.num)?;
                    }
                }
                Ok(0xff)
            }
        }
    }

    fn blocksize_of_cipher(&self) -> usize {
        match self.kind {
            Kind::Block { algorithm, .. } => algorithm.block_size(),
            _ => 0,
        }
    }

    /// `chacha20_cipher`.
    fn chacha(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.chacha.as_mut().ok_or(Error::Internal)?.apply(data)
    }

    /// The cipher.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// The IV's length (`ivlen`).
    pub fn iv_len(&self) -> usize {
        self.ivlen
    }

    /// The key length (`keylen`).
    pub fn key_len(&self) -> usize {
        self.keylen
    }

    /// Whether padding is on.
    pub fn padding(&self) -> bool {
        self.pad
    }

    /// The partial-block position (`num`).
    pub fn num(&self) -> u32 {
        self.num
    }

    /// The IV as set, all 16 octets of the context's buffer (the IV is the first `ivlen`).
    pub fn original_iv(&mut self) -> &mut [u8; MAX_BLOCK] {
        &mut self.oiv
    }

    /// The running IV, likewise.
    pub fn updated_iv(&mut self) -> &mut [u8; MAX_BLOCK] {
        &mut self.iv
    }

    /// Sets padding on or off (`padding`).
    pub fn set_padding(&mut self, on: bool) {
        self.pad = on;
    }

    /// Sets CFB1 to count bits or octets (`use-bits`).
    pub fn set_use_bits(&mut self, on: bool) {
        self.use_bits = on;
    }

    /// Sets the TLS version for record padding (`tls-version`): only 0 (none) until the TLS
    /// step, where libssl sets it (docs/DEVIATIONS.md).
    pub fn set_tls_version(&mut self, version: u32) -> Result<(), Error> {
        if version != 0 {
            return Err(Error::FailedToGetParameter);
        }
        Ok(())
    }

    /// The TLS MAC length (`tls-mac-size`).
    pub fn tls_mac_size(&self) -> usize {
        self.tlsmacsize
    }

    /// Sets the TLS MAC length.
    pub fn set_tls_mac_size(&mut self, size: usize) {
        self.tlsmacsize = size;
    }

    /// Sets `num`: below the block size (so only 0 for the stream modes, whose block size is
    /// 1, as in the reference).
    pub fn set_num(&mut self, num: u32) -> Result<(), Error> {
        if self.blocksize > 0 && usize::try_from(num).map_or(true, |n| n >= self.blocksize) {
            return Err(Error::FailedToGetParameter);
        }
        self.num = num;
        Ok(())
    }

    /// `tdes_generatekey`: a random key of the key length into `key` with odd parity in each
    /// DES key, from `fill` (the library context's private random generator).
    pub fn random_key(
        &self,
        key: &mut [u8],
        fill: impl FnOnce(&mut [u8]) -> bool,
    ) -> Result<(), Error> {
        let kl = self.keylen;
        let k = key.get_mut(..kl).ok_or(Error::FailedToGenerateKey)?;
        if kl == 0 || !fill(k) {
            return Err(Error::FailedToGenerateKey);
        }
        for (i, b) in k.iter_mut().enumerate() {
            // Only the first three DES keys, as DES_set_odd_parity on deskey[0..3].
            if i < 24 {
                *b = odd_parity(*b);
            }
        }
        Ok(())
    }

    /// Whether the context is set to encrypt.
    pub fn encrypting(&self) -> bool {
        self.enc
    }
}

/// A DES key octet with odd parity (its low bit set so the octet has an odd number of ones).
fn odd_parity(b: u8) -> u8 {
    let high = b & 0xfe;
    if high.count_ones().is_multiple_of(2) {
        high | 1
    } else {
        high
    }
}

/// `ossl_cipher_unpadblock` in constant time: the length without PKCS#7 padding, or
/// `BadDecrypt`. `block` is a whole block (at most 16 octets).
fn unpad(block: &[u8]) -> Result<usize, Error> {
    let bs = u16::try_from(block.len()).map_err(|_| Error::Internal)?;
    let pad = block.last().copied().unwrap_or(0);
    let padn = u16::from(pad);
    // All ones while the padding checks out, examined over the whole block whatever it holds.
    let mut good: u8 = !ct_is_zero(pad) & ct_le(padn, bs);
    for (i, &b) in (0u16..).zip(block) {
        // Octet i is padding when i + pad >= bs.
        let in_pad = ct_le(bs, i.wrapping_add(padn));
        good &= !in_pad | ct_is_zero(b ^ pad);
    }
    if good == 0xff {
        Ok(usize::from(bs.wrapping_sub(padn)))
    } else {
        Err(Error::BadDecrypt)
    }
}

/// 0xff if `a` is 0, else 0, without branching.
fn ct_is_zero(a: u8) -> u8 {
    ((a | a.wrapping_neg()) >> 7).wrapping_sub(1)
}

/// 0xff if `a <= b`, else 0, without branching, for both below 2^15.
#[allow(clippy::cast_possible_truncation)]
fn ct_le(a: u16, b: u16) -> u8 {
    // b - a borrows into the top bit exactly when a > b.
    let borrow = (b.wrapping_sub(a) >> 15) as u8;
    borrow.wrapping_sub(1)
}

/// CBC in place over whole blocks (`CRYPTO_cbc128_encrypt`/`_decrypt`, DES's CBC).
fn cbc(cipher: &dyn BlockCipher, iv: &mut [u8], data: &mut [u8], enc: bool) -> Result<(), Error> {
    let bs = iv.len();
    for block in data.chunks_mut(bs) {
        if block.len() != bs {
            return Err(Error::Internal);
        }
        if enc {
            for (b, v) in block.iter_mut().zip(iv.iter()) {
                *b ^= v;
            }
            cipher
                .encrypt_blocks(block)
                .map_err(|_| Error::CipherOperationFailed)?;
            iv.copy_from_slice(block);
        } else {
            let mut c = Zeroizing::new([0u8; MAX_BLOCK]);
            let saved = c.get_mut(..bs).ok_or(Error::Internal)?;
            saved.copy_from_slice(block);
            cipher
                .decrypt_blocks(block)
                .map_err(|_| Error::CipherOperationFailed)?;
            for (b, v) in block.iter_mut().zip(iv.iter()) {
                *b ^= v;
            }
            iv.copy_from_slice(saved);
        }
    }
    Ok(())
}

/// Encrypts the IV in place (the key stream block for OFB, CFB, and CTR).
fn encrypt_iv(cipher: &dyn BlockCipher, iv: &mut [u8]) -> Result<(), Error> {
    cipher
        .encrypt_blocks(iv)
        .map_err(|_| Error::CipherOperationFailed)
}

/// The next position within a block of `bs`.
fn next(n: usize, bs: usize) -> usize {
    n.wrapping_add(1).checked_rem(bs).unwrap_or(0)
}

/// OFB (`CRYPTO_ofb128_encrypt`, `DES_ede3_ofb64_encrypt`): the IV holds the key stream; `num`
/// is the position in it.
fn ofb(cipher: &dyn BlockCipher, iv: &mut [u8], data: &mut [u8], num: u32) -> Result<u32, Error> {
    let bs = iv.len();
    let mut n = usize::try_from(num)
        .map_err(|_| Error::Internal)?
        .checked_rem(bs)
        .unwrap_or(0);
    for b in data.iter_mut() {
        if n == 0 {
            encrypt_iv(cipher, iv)?;
        }
        *b ^= iv.get(n).copied().ok_or(Error::Internal)?;
        n = next(n, bs);
    }
    u32::try_from(n).map_err(|_| Error::Internal)
}

/// CFB with the block's feedback (`CRYPTO_cfb128_encrypt`, `DES_ede3_cfb64_encrypt`).
fn cfb(
    cipher: &dyn BlockCipher,
    iv: &mut [u8],
    data: &mut [u8],
    num: u32,
    enc: bool,
) -> Result<u32, Error> {
    let bs = iv.len();
    let mut n = usize::try_from(num)
        .map_err(|_| Error::Internal)?
        .checked_rem(bs)
        .unwrap_or(0);
    for b in data.iter_mut() {
        if n == 0 {
            encrypt_iv(cipher, iv)?;
        }
        let k = iv.get_mut(n).ok_or(Error::Internal)?;
        if enc {
            *b ^= *k;
            *k = *b;
        } else {
            let c = *b;
            *b ^= *k;
            *k = c;
        }
        n = next(n, bs);
    }
    u32::try_from(n).map_err(|_| Error::Internal)
}

/// One step of CFB with `nbits` (1 or 8) of feedback (`cfbr_encrypt_block`,
/// `DES_ede3_cfb_encrypt`): the octet out for `input`, whose top `nbits` matter, the IV shifted
/// left by `nbits` with the ciphertext's bits coming in.
fn cfb_shift(
    cipher: &dyn BlockCipher,
    iv: &mut [u8],
    input: u8,
    nbits: u32,
    enc: bool,
) -> Result<u8, Error> {
    let bs = iv.len();
    let mut ks = Zeroizing::new([0u8; MAX_BLOCK]);
    let block = ks.get_mut(..bs).ok_or(Error::Internal)?;
    block.copy_from_slice(iv);
    encrypt_iv(cipher, block)?;
    let out = input ^ block.first().copied().ok_or(Error::Internal)?;
    let fed = if enc { out } else { input };
    if nbits == 8 {
        iv.copy_within(1.., 0);
        if let Some(last) = iv.last_mut() {
            *last = fed;
        }
    } else {
        // Shift the whole IV left a bit; the fed octet's top bit comes in.
        let mut carry = fed >> 7;
        for v in iv.iter_mut().rev() {
            let top = *v >> 7;
            *v = (*v << 1) | carry;
            carry = top;
        }
    }
    Ok(out)
}

/// CFB1 (`CRYPTO_cfb128_1_encrypt`, the triple-DES CFB1): `bits` bits, most significant first.
/// Returns the mask of the bits written in the last octet.
fn cfb1(
    cipher: &dyn BlockCipher,
    iv: &mut [u8],
    data: &mut [u8],
    bits: usize,
    enc: bool,
) -> Result<u8, Error> {
    for n in 0..bits {
        let octet = data.get_mut(n / 8).ok_or(Error::Internal)?;
        let shift = 7usize.wrapping_sub(n % 8);
        let bit = (*octet >> shift) & 1;
        let out = cfb_shift(cipher, iv, bit << 7, 1, enc)?;
        *octet = (*octet & !(1 << shift)) | ((out >> 7) << shift);
    }
    let rem = bits % 8;
    Ok(if rem == 0 {
        0xff
    } else {
        0xffu8 << 8usize.wrapping_sub(rem)
    })
}

/// CTR with a 128-bit big-endian counter in the IV (`CRYPTO_ctr128_encrypt`): `ks` holds the
/// current key stream block, `num` the position in it.
fn ctr(
    cipher: &dyn BlockCipher,
    counter: &mut [u8],
    ks: &mut [u8],
    data: &mut [u8],
    num: u32,
) -> Result<u32, Error> {
    let bs = counter.len();
    let mut n = usize::try_from(num)
        .map_err(|_| Error::Internal)?
        .checked_rem(bs)
        .unwrap_or(0);
    for b in data.iter_mut() {
        if n == 0 {
            ks.copy_from_slice(counter);
            encrypt_iv(cipher, ks)?;
            // ctr128_inc: the whole counter, big-endian.
            for c in counter.iter_mut().rev() {
                *c = c.wrapping_add(1);
                if *c != 0 {
                    break;
                }
            }
        }
        *b ^= ks.get(n).copied().ok_or(Error::Internal)?;
        n = next(n, bs);
    }
    u32::try_from(n).map_err(|_| Error::Internal)
}
