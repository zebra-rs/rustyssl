//! The default provider's digest algorithms with the semantics of their provider functions
//! (`providers/implementations/digests/`): what `init`, `update`, `final`, `squeeze`, and the
//! context parameters do to a context, which the EVP layer drives through the provider's
//! dispatch table.
//!
//! - **Plain digests** (SHA-1, SHA-2, SM3, MD5, MD5-SHA1, RIPEMD-160, NULL) run the digest
//!   backend; `final` needs room for the whole digest. SHA2-256/192 is SHA-256 truncated to 24
//!   octets, as the reference defines it. SHA-1 and MD5-SHA1 take SSLv3's master secret
//!   (`ssl3-ms`), which turns the context into SSLv3's handshake hash.
//! - **The Keccak family** (SHA-3, KECCAK, SHAKE, KECCAK-KMAC) is a port of the reference's
//!   `KECCAK1600_CTX`: one buffer serves absorbing and, after the first squeeze, holds the rest
//!   of a squeezed block, and the state moves from init to absorbing to squeezing or final.
//!   The reference's quirks follow from it: data given after a squeeze isn't absorbed (and can
//!   shift the buffered output), `final` after a squeeze fails, an XOF's length persists across
//!   re-initialization, and SHAKE has no default length.
//! - **BLAKE2** keeps the reference's two lengths: the `size` parameter, applied at the next
//!   `init`, and the length the running hash has.
//!
//! One deviation: `final` of a fixed-size Keccak digest writes the whole digest whatever room
//! it's given, so `EVP_DigestFinalXOF` with a short length overflows the caller's buffer in the
//! reference. Here it writes only the room given (docs/DEVIATIONS.md).

use zeroize::Zeroize;

use crate::{mac, md};

/// The default provider's digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum Kind {
    Sha1,
    Sha224,
    Sha256,
    Sha256_192,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Keccak224,
    Keccak256,
    Keccak384,
    Keccak512,
    KeccakKmac128,
    KeccakKmac256,
    Shake128,
    Shake256,
    Blake2s256,
    Blake2b512,
    Sm3,
    Md5,
    Md5Sha1,
    Ripemd160,
    Null,
}

/// Why a provider function failed, for the error it raises (`ERR_LIB_PROV`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// No error is raised: the function returns 0.
    Silent,
    /// `PROV_R_INVALID_DIGEST_LENGTH`: SHAKE with no length set.
    InvalidDigestLength,
    /// `PROV_R_INVALID_DIGEST_SIZE`: a BLAKE2 size out of range, or too little room.
    InvalidDigestSize,
}

impl Kind {
    /// The block size the digest reports.
    pub const fn block_size(self) -> usize {
        match self {
            Self::Sha384 | Self::Sha512 | Self::Sha512_224 | Self::Sha512_256 => 128,
            Self::Blake2b512 => 128,
            Self::Sha3_224 | Self::Keccak224 => 144,
            Self::Sha3_256 | Self::Keccak256 | Self::Shake256 | Self::KeccakKmac256 => 136,
            Self::Sha3_384 | Self::Keccak384 => 104,
            Self::Sha3_512 | Self::Keccak512 => 72,
            Self::Shake128 | Self::KeccakKmac128 => 168,
            Self::Null => 0,
            _ => 64,
        }
    }

    /// The size the digest reports (0 for SHAKE, which has no default length).
    pub const fn size(self) -> usize {
        match self {
            Self::Sha1 | Self::Ripemd160 => 20,
            Self::Sha224 | Self::Sha512_224 | Self::Sha3_224 | Self::Keccak224 => 28,
            Self::Sha256_192 => 24,
            Self::Sha256
            | Self::Sha512_256
            | Self::Sha3_256
            | Self::Keccak256
            | Self::Blake2s256
            | Self::Sm3
            | Self::KeccakKmac128 => 32,
            Self::Sha384 | Self::Sha3_384 | Self::Keccak384 => 48,
            Self::Sha512 | Self::Sha3_512 | Self::Keccak512 | Self::Blake2b512 => 64,
            Self::KeccakKmac256 => 64,
            Self::Md5 => 16,
            Self::Md5Sha1 => 36,
            Self::Shake128 | Self::Shake256 | Self::Null => 0,
        }
    }

    /// Whether the digest is an XOF (SHAKE, KECCAK-KMAC).
    pub const fn is_xof(self) -> bool {
        matches!(
            self,
            Self::Shake128 | Self::Shake256 | Self::KeccakKmac128 | Self::KeccakKmac256
        )
    }

    /// Whether a signature's AlgorithmIdentifier leaves the parameters out (SHA-1, SHA-2,
    /// SHA-3, KECCAK, SHAKE).
    pub const fn algid_absent(self) -> bool {
        matches!(
            self,
            Self::Sha1
                | Self::Sha224
                | Self::Sha256
                | Self::Sha256_192
                | Self::Sha384
                | Self::Sha512
                | Self::Sha512_224
                | Self::Sha512_256
                | Self::Sha3_224
                | Self::Sha3_256
                | Self::Sha3_384
                | Self::Sha3_512
                | Self::Keccak224
                | Self::Keccak256
                | Self::Keccak384
                | Self::Keccak512
                | Self::Shake128
                | Self::Shake256
        )
    }

    /// The backend digest a plain digest runs.
    const fn backend(self) -> Option<md::Algorithm> {
        Some(match self {
            Self::Sha1 => md::Algorithm::Sha1,
            Self::Sha224 => md::Algorithm::Sha224,
            Self::Sha256 | Self::Sha256_192 => md::Algorithm::Sha256,
            Self::Sha384 => md::Algorithm::Sha384,
            Self::Sha512 => md::Algorithm::Sha512,
            Self::Sha512_224 => md::Algorithm::Sha512_224,
            Self::Sha512_256 => md::Algorithm::Sha512_256,
            Self::Sm3 => md::Algorithm::Sm3,
            Self::Md5 => md::Algorithm::Md5,
            Self::Ripemd160 => md::Algorithm::Ripemd160,
            Self::Null => md::Algorithm::Null,
            _ => return None,
        })
    }
}

/// A provider digest context (`newctx`).
pub enum Ctx {
    /// A plain digest over the backend.
    Plain(Plain),
    /// MD5 and SHA-1 side by side, separately for SSLv3.
    Md5Sha1(Box<dyn md::Context>, Box<dyn md::Context>),
    /// The Keccak family.
    Keccak(Box<Keccak>),
    /// BLAKE2s or BLAKE2b.
    Blake2(Blake2),
}

/// A plain digest.
pub struct Plain {
    kind: Kind,
    ctx: Box<dyn md::Context>,
}

impl Clone for Ctx {
    fn clone(&self) -> Self {
        match self {
            Self::Plain(p) => Self::Plain(Plain {
                kind: p.kind,
                ctx: p.ctx.clone_box(),
            }),
            Self::Md5Sha1(a, b) => Self::Md5Sha1(a.clone_box(), b.clone_box()),
            Self::Keccak(k) => Self::Keccak(k.clone()),
            Self::Blake2(b) => Self::Blake2(b.clone()),
        }
    }
}

/// Writes the first `out.len()` octets of a finished `ctx` of `size` octets.
fn finish(ctx: &mut dyn md::Context, size: usize, out: &mut [u8]) -> bool {
    let mut digest = zeroize::Zeroizing::new(vec![0u8; size]);
    if ctx.finalize(&mut digest).is_err() {
        return false;
    }
    let n = out.len().min(size);
    out.get_mut(..n)
        .zip(digest.get(..n))
        .map(|(o, d)| o.copy_from_slice(d))
        .is_some()
}

impl Ctx {
    /// A new context (the provider's `newctx`).
    pub fn new(kind: Kind) -> Self {
        if let Some(alg) = kind.backend() {
            return Self::Plain(Plain {
                kind,
                ctx: md::context(alg),
            });
        }
        match kind {
            Kind::Md5Sha1 => Self::Md5Sha1(
                md::context(md::Algorithm::Md5),
                md::context(md::Algorithm::Sha1),
            ),
            Kind::Blake2s256 | Kind::Blake2b512 => Self::Blake2(Blake2::new(kind)),
            _ => Self::Keccak(Box::new(Keccak::new(kind))),
        }
    }

    /// `init` (after any parameters `init` takes are set).
    pub fn init(&mut self) -> bool {
        match self {
            Self::Plain(p) => p.ctx.reset(),
            Self::Md5Sha1(a, b) => {
                a.reset();
                b.reset();
            }
            Self::Keccak(k) => k.reset(),
            Self::Blake2(b) => return b.init(),
        }
        true
    }

    /// `update`.
    pub fn update(&mut self, data: &[u8]) -> bool {
        match self {
            Self::Plain(p) => p.ctx.update(data).is_ok(),
            Self::Md5Sha1(a, b) => a.update(data).is_ok() && b.update(data).is_ok(),
            Self::Keccak(k) => {
                k.update(data);
                true
            }
            Self::Blake2(b) => b.update(data),
        }
    }

    /// `final` into `out` (its length is `outsz`, the room the caller gives): the length the
    /// digest reports (`*outl`), or why it failed. Some failures still report a length, as the
    /// reference sets `*outl` before failing; `outl` gets it either way.
    pub fn finalize(&mut self, out: &mut [u8], outl: &mut usize) -> Result<(), Error> {
        match self {
            Self::Plain(p) => {
                let size = p.kind.size();
                if out.len() < size {
                    return Err(Error::Silent);
                }
                let full = p.kind.backend().map_or(0, md::Algorithm::output_size);
                if !finish(&mut *p.ctx, full, out.get_mut(..size).unwrap_or(&mut [])) {
                    return Err(Error::Silent);
                }
                *outl = size;
                Ok(())
            }
            Self::Md5Sha1(a, b) => {
                if out.len() < 36 {
                    return Err(Error::Silent);
                }
                let (m, s) = out.split_at_mut(16);
                if !finish(&mut **a, 16, m)
                    || !finish(&mut **b, 20, s.get_mut(..20).unwrap_or(&mut []))
                {
                    return Err(Error::Silent);
                }
                *outl = 36;
                Ok(())
            }
            Self::Keccak(k) => k.finalize(out, outl),
            Self::Blake2(b) => b.finalize(out, outl),
        }
    }

    /// Whether `squeeze` can run. KECCAK-KMAC's dispatch table has `squeeze`, but on the
    /// reference's generic and ARMv8 builds its context gets SHA-3's methods, which have none,
    /// so it always fails without an error (and without storing a length).
    pub fn can_squeeze(&self) -> bool {
        matches!(self, Self::Keccak(k) if matches!(k.kind, Kind::Shake128 | Kind::Shake256))
    }

    /// `squeeze` (SHAKE only, see [`Ctx::can_squeeze`]).
    pub fn squeeze(&mut self, out: &mut [u8]) -> bool {
        if !self.can_squeeze() {
            return false;
        }
        match self {
            Self::Keccak(k) => k.squeeze(out),
            _ => false,
        }
    }

    /// The `xoflen`/`size` context parameter of SHAKE and KECCAK-KMAC.
    pub fn xof_length(&self) -> Option<usize> {
        match self {
            Self::Keccak(k) if k.kind.is_xof() => Some(k.md_size),
            _ => None,
        }
    }

    /// Sets the `xoflen`/`size` context parameter of SHAKE and KECCAK-KMAC.
    pub fn set_xof_length(&mut self, n: usize) {
        if let Self::Keccak(k) = self {
            k.md_size = n;
        }
    }

    /// BLAKE2's `size` context parameter (as the reference reads it, the length the next
    /// `init` uses, which `init` sets to the running one).
    pub fn blake2_size(&self) -> Option<u8> {
        match self {
            Self::Blake2(b) => Some(b.digest_length),
            _ => None,
        }
    }

    /// Sets BLAKE2's `size` for the next `init`: 1 to the digest's size.
    pub fn set_blake2_size(&mut self, size: usize) -> Result<(), Error> {
        match self {
            Self::Blake2(b) => b.set_size(size),
            _ => Ok(()),
        }
    }

    /// SSLv3's master secret (`ssl3-ms`, RFC 6101 5.6.8) for SHA-1 and MD5-SHA1: the hash so
    /// far with the secret and pad 1, then the secret and pad 2 before it. Only a 48-octet
    /// secret is taken.
    pub fn ssl3_master_secret(&mut self, ms: &[u8]) -> bool {
        if ms.len() != 48 {
            return false;
        }
        match self {
            Self::Plain(p) if p.kind == Kind::Sha1 => ssl3(&mut *p.ctx, ms, 40, 20),
            Self::Md5Sha1(m, s) => ssl3(&mut **m, ms, 48, 16) && ssl3(&mut **s, ms, 40, 20),
            _ => false,
        }
    }
}

/// SSLv3's transform of one hash: `inner = H(hash || ms || pad1)`, then
/// `hash = H-context(ms || pad2 || inner)`.
fn ssl3(ctx: &mut dyn md::Context, ms: &[u8], pad: usize, size: usize) -> bool {
    let mut inner = zeroize::Zeroizing::new(vec![0u8; size]);
    let ok = ctx.update(ms).is_ok()
        && ctx.update(&vec![0x36; pad]).is_ok()
        && ctx.finalize(&mut inner).is_ok();
    if !ok {
        return false;
    }
    ctx.reset();
    ctx.update(ms).is_ok() && ctx.update(&vec![0x5c; pad]).is_ok() && ctx.update(&inner).is_ok()
}

// ---------------------------------------------------------------------------------------------
// The Keccak family

#[derive(Clone, Copy, PartialEq, Eq)]
enum XofState {
    Init,
    Absorb,
    Final,
    Squeeze,
}

/// The reference's `KECCAK1600_CTX` with its generic absorb, final, and squeeze.
#[derive(Clone)]
pub struct Keccak {
    kind: Kind,
    a: [u64; 25],
    block_size: usize,
    /// The output length; `usize::MAX` for SHAKE with none set.
    md_size: usize,
    buf: [u8; 168],
    bufsz: usize,
    pad: u8,
    state: XofState,
}

impl Drop for Keccak {
    fn drop(&mut self) {
        self.a.zeroize();
        self.buf.zeroize();
    }
}

impl Keccak {
    fn new(kind: Kind) -> Self {
        let (pad, md_size) = match kind {
            Kind::Keccak224 | Kind::Keccak256 | Kind::Keccak384 | Kind::Keccak512 => {
                (0x01, kind.size())
            }
            Kind::Shake128 | Kind::Shake256 => (0x1f, usize::MAX),
            Kind::KeccakKmac128 | Kind::KeccakKmac256 => (0x04, kind.size()),
            _ => (0x06, kind.size()),
        };
        Self {
            kind,
            a: [0; 25],
            block_size: kind.block_size(),
            md_size,
            buf: [0; 168],
            bufsz: 0,
            pad,
            state: XofState::Init,
        }
    }

    /// `ossl_sha3_reset`.
    fn reset(&mut self) {
        self.a = [0; 25];
        self.bufsz = 0;
        self.state = XofState::Init;
    }

    fn permute(&mut self) {
        keccak::Keccak::new().with_f1600(|f| f(&mut self.a));
    }

    /// `SHA3_absorb`: whole blocks of `data` into the state; the length left over.
    fn absorb_blocks(&mut self, data: &[u8]) -> usize {
        let r = self.block_size;
        let mut blocks = data.chunks_exact(r);
        for block in blocks.by_ref() {
            for (lane, bytes) in self.a.iter_mut().zip(block.as_chunks::<8>().0) {
                *lane ^= u64::from_le_bytes(*bytes);
            }
            self.permute();
        }
        blocks.remainder().len()
    }

    /// `SHA3_squeeze`: `out.len()` octets, permuting first if `next`.
    fn squeeze_blocks(&mut self, out: &mut [u8], mut next: bool) {
        let r = self.block_size;
        for chunk in out.chunks_mut(r) {
            if next {
                self.permute();
            }
            next = true;
            for (bytes, lane) in chunk.chunks_mut(8).zip(self.a) {
                let lane = lane.to_le_bytes();
                bytes.copy_from_slice(lane.get(..bytes.len()).unwrap_or(&[]));
            }
        }
    }

    /// `generic_sha3_absorb`: nothing once squeezing or final (0 left over).
    fn absorb(&mut self, data: &[u8]) -> usize {
        if !matches!(self.state, XofState::Init | XofState::Absorb) {
            return 0;
        }
        self.state = XofState::Absorb;
        self.absorb_blocks(data)
    }

    /// `keccak_update`.
    fn update(&mut self, mut data: &[u8]) {
        let bsz = self.block_size;
        if data.is_empty() {
            return;
        }
        if self.bufsz != 0 {
            let rem = bsz.saturating_sub(self.bufsz);
            if data.len() < rem {
                if let Some(dst) = self
                    .buf
                    .get_mut(self.bufsz..self.bufsz.saturating_add(data.len()))
                {
                    dst.copy_from_slice(data);
                }
                self.bufsz = self.bufsz.saturating_add(data.len());
                return;
            }
            let (head, rest) = data.split_at(rem);
            if let Some(dst) = self.buf.get_mut(self.bufsz..bsz) {
                dst.copy_from_slice(head);
            }
            data = rest;
            let block = self.buf;
            self.absorb(block.get(..bsz).unwrap_or(&[]));
            self.bufsz = 0;
        }
        let rem = self.absorb(data);
        if rem != 0 {
            let tail = data.get(data.len().saturating_sub(rem)..).unwrap_or(&[]);
            if let Some(dst) = self.buf.get_mut(..rem) {
                dst.copy_from_slice(tail);
            }
            self.bufsz = rem;
        }
    }

    /// Pads the buffered data with `10*1` and absorbs the last block.
    fn pad_and_absorb(&mut self) {
        let bsz = self.block_size;
        let num = self.bufsz;
        if let Some(rest) = self.buf.get_mut(num..bsz) {
            rest.fill(0);
        }
        if let Some(b) = self.buf.get_mut(num) {
            *b = self.pad;
        }
        if let Some(b) = self.buf.get_mut(bsz.saturating_sub(1)) {
            *b |= 0x80;
        }
        let block = self.buf;
        self.absorb_blocks(block.get(..bsz).unwrap_or(&[]));
    }

    /// `keccak_final` with `ossl_sha3_final`: `md_size` octets (at most `out.len()`, the
    /// deviation), when the caller gives any room.
    fn finalize(&mut self, out: &mut [u8], outl: &mut usize) -> Result<(), Error> {
        if self.md_size == usize::MAX {
            return Err(Error::InvalidDigestLength);
        }
        let mut ok = true;
        if !out.is_empty() && self.md_size != 0 {
            if matches!(self.state, XofState::Squeeze | XofState::Final) {
                ok = false;
            } else {
                self.pad_and_absorb();
                self.state = XofState::Final;
                let n = self.md_size.min(out.len());
                self.squeeze_blocks(out.get_mut(..n).unwrap_or(&mut []), false);
            }
        }
        *outl = self.md_size;
        if ok { Ok(()) } else { Err(Error::Silent) }
    }

    /// `shake_squeeze` with `ossl_sha3_squeeze`: callable repeatedly; fails after `final`.
    fn squeeze(&mut self, mut out: &mut [u8]) -> bool {
        let bsz = self.block_size;
        if out.is_empty() {
            return true;
        }
        if self.state == XofState::Final {
            return false;
        }
        let mut next = true;
        if self.state != XofState::Squeeze {
            self.pad_and_absorb();
            self.state = XofState::Squeeze;
            self.bufsz = 0;
            next = false;
        }
        // Octets left over from the last squeezed block, at the end of the buffer.
        if self.bufsz != 0 {
            let len = out.len().min(self.bufsz);
            let from = bsz.saturating_sub(self.bufsz);
            let (head, rest) = out.split_at_mut(len);
            if let Some(src) = self.buf.get(from..from.saturating_add(len)) {
                head.copy_from_slice(src);
            }
            out = rest;
            self.bufsz = self.bufsz.saturating_sub(len);
        }
        if out.is_empty() {
            return true;
        }
        let whole = out.len().checked_div(bsz).unwrap_or(0).saturating_mul(bsz);
        if whole > 0 {
            let (head, rest) = out.split_at_mut(whole);
            self.squeeze_blocks(head, next);
            next = true;
            out = rest;
        }
        if !out.is_empty() {
            let mut block = [0u8; 168];
            self.squeeze_blocks(block.get_mut(..bsz).unwrap_or(&mut []), next);
            self.buf = block;
            if let Some(src) = self.buf.get(..out.len()) {
                out.copy_from_slice(src);
            }
            self.bufsz = bsz.saturating_sub(out.len());
            block.zeroize();
        }
        true
    }
}

// ---------------------------------------------------------------------------------------------
// BLAKE2

/// The BLAKE2 digests: the `size` for the next `init` and the running hash.
pub struct Blake2 {
    kind: Kind,
    /// `params.digest_length`: 0 until set or initialized.
    digest_length: u8,
    running: Option<(Box<dyn mac::Mac>, usize)>,
}

impl Clone for Blake2 {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind,
            digest_length: self.digest_length,
            running: self.running.as_ref().map(|(m, n)| (m.clone_box(), *n)),
        }
    }
}

impl Blake2 {
    fn new(kind: Kind) -> Self {
        Self {
            kind,
            digest_length: 0,
            running: None,
        }
    }

    fn max(&self) -> usize {
        self.kind.size()
    }

    fn set_size(&mut self, size: usize) -> Result<(), Error> {
        if size == 0 || size > self.max() {
            return Err(Error::InvalidDigestSize);
        }
        self.digest_length = u8::try_from(size).map_err(|_| Error::InvalidDigestSize)?;
        Ok(())
    }

    fn init(&mut self) -> bool {
        if self.digest_length == 0 {
            self.digest_length = u8::try_from(self.max()).unwrap_or(0);
        }
        let size = usize::from(self.digest_length);
        let alg = if self.kind == Kind::Blake2b512 {
            mac::Blake2Algorithm::Blake2b
        } else {
            mac::Blake2Algorithm::Blake2s
        };
        match mac::blake2_unkeyed(alg, size) {
            Ok(m) => {
                self.running = Some((m, size));
                true
            }
            Err(_) => false,
        }
    }

    /// Before a successful `init` (one whose `size` was refused), the reference's context is
    /// zeroed: updates succeed, and a final has a length of 0, so it writes nothing and
    /// succeeds. No output depends on that state, so it's modeled as accepting and ignoring.
    fn update(&mut self, data: &[u8]) -> bool {
        match self.running.as_mut() {
            Some((m, _)) => m.update(data).is_ok(),
            None => true,
        }
    }

    fn finalize(&mut self, out: &mut [u8], outl: &mut usize) -> Result<(), Error> {
        let Some((m, size)) = self.running.as_mut() else {
            *outl = 0;
            return Ok(());
        };
        *outl = *size;
        if out.is_empty() {
            return Ok(());
        }
        if out.len() < *size {
            return Err(Error::InvalidDigestSize);
        }
        m.finalize(out.get_mut(..*size).unwrap_or(&mut []))
            .map_err(|_| Error::Silent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(kind: Kind, data: &[u8], len: usize) -> Vec<u8> {
        let mut c = Ctx::new(kind);
        assert!(c.init());
        assert!(c.update(data));
        let mut out = vec![0u8; len];
        let mut outl = 0;
        c.finalize(&mut out, &mut outl).unwrap();
        out.truncate(outl);
        out
    }

    #[test]
    fn the_keccak_port_agrees_with_the_backend() {
        let data: Vec<u8> = (0..1000u32)
            .map(|i| u8::try_from((i * 7 + 3) % 256).unwrap())
            .collect();
        for (kind, alg) in [
            (Kind::Sha3_224, md::Algorithm::Sha3_224),
            (Kind::Sha3_256, md::Algorithm::Sha3_256),
            (Kind::Sha3_384, md::Algorithm::Sha3_384),
            (Kind::Sha3_512, md::Algorithm::Sha3_512),
        ] {
            for len in [0, 1, 71, 72, 73, 135, 136, 137, 1000] {
                let mut want = vec![0u8; kind.size()];
                let mut b = md::context(alg);
                b.update(&data[..len]).unwrap();
                b.finalize(&mut want).unwrap();
                assert_eq!(digest(kind, &data[..len], 64), want, "{kind:?} {len}");
            }
        }
        // SHAKE squeezed in pieces equals one long squeeze.
        let mut whole = Ctx::new(Kind::Shake128);
        whole.init();
        whole.update(&data);
        let mut long = vec![0u8; 500];
        assert!(whole.squeeze(&mut long));
        let mut b = md::context(md::Algorithm::Shake128);
        b.update(&data).unwrap();
        let mut want = vec![0u8; 500];
        b.finalize(&mut want).unwrap();
        assert_eq!(long, want);
        let mut pieces = Ctx::new(Kind::Shake128);
        pieces.init();
        pieces.update(&data);
        let mut got = Vec::new();
        for n in [1, 7, 168, 3, 200, 121] {
            let mut part = vec![0u8; n];
            assert!(pieces.squeeze(&mut part));
            got.extend(part);
        }
        assert_eq!(got, want);
    }

    #[test]
    fn sha256_192_is_truncated_sha256() {
        assert_eq!(
            digest(Kind::Sha256_192, b"abc", 32),
            digest(Kind::Sha256, b"abc", 32)[..24]
        );
    }
}
