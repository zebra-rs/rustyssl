//! The legacy provider's RC4-HMAC-MD5 (`cipher_rc4_hmac_md5.c`, `cipher_rc4_hmac_md5_hw.c`):
//! RC4 with HMAC-MD5 for TLS records, which a caller drives with the record's 13-octet
//! additional data (`tls1-aad`) and the MAC key (`mackey`).
//!
//! Without additional data it is RC4 (with MD5 running over the data, unused). With it, the
//! next call is one record: encryption appends the HMAC of the header and the payload and
//! encrypts both; decryption decrypts, then checks the HMAC in constant time and fails if it
//! doesn't match. This is the reference's portable path; its x86_64 assembly computes the same
//! result.

use crate::md;
use crate::sym::{self, KeyStream};

/// MD5's digest length.
const MD5_LEN: usize = 16;

/// The additional data's length (`EVP_AEAD_TLS1_AAD_LEN`).
const TLS1_AAD_LEN: usize = 13;

/// Why an operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The record didn't have the length the additional data announced, or its MAC didn't
    /// match (`hw->cipher` failing).
    Cipher,
    /// No key.
    NoKey,
}

/// The cipher's context (`PROV_RC4_HMAC_MD5_CTX`).
pub struct Ctx {
    enc: bool,
    key_len: usize,
    key_set: bool,
    stream: Option<Box<dyn KeyStream>>,
    /// The inner hash's start (the MAC key XOR ipad), the outer's (opad), and the running one.
    head: Box<dyn md::Context>,
    tail: Box<dyn md::Context>,
    md: Box<dyn md::Context>,
    /// The record's payload length from the additional data (`NO_PAYLOAD_LENGTH`: `None`).
    payload: Option<usize>,
    /// What `tls1-aad` returned (`tls-aad-pad`).
    pub tls_aad_pad: usize,
    /// `tls-version`.
    pub tls_version: u32,
}

impl Clone for Ctx {
    fn clone(&self) -> Self {
        Self {
            enc: self.enc,
            key_len: self.key_len,
            key_set: self.key_set,
            stream: self.stream.as_ref().and_then(|s| s.clone_box().ok()),
            head: self.head.clone_box(),
            tail: self.tail.clone_box(),
            md: self.md.clone_box(),
            payload: self.payload,
            tls_aad_pad: self.tls_aad_pad,
            tls_version: self.tls_version,
        }
    }
}

impl Default for Ctx {
    fn default() -> Self {
        Self::new()
    }
}

impl Ctx {
    /// A new context: a 16-octet key, no key set.
    pub fn new() -> Self {
        Self {
            enc: false,
            key_len: 16,
            key_set: false,
            stream: None,
            head: md::context(md::Algorithm::Md5),
            tail: md::context(md::Algorithm::Md5),
            md: md::context(md::Algorithm::Md5),
            payload: None,
            tls_aad_pad: 0,
            tls_version: 0,
        }
    }

    /// The key length.
    pub fn key_len(&self) -> usize {
        self.key_len
    }

    /// Whether a key is set.
    pub fn key_set(&self) -> bool {
        self.key_set
    }

    /// Whether the context encrypts.
    pub fn encrypting(&self) -> bool {
        self.enc
    }

    /// `einit`/`dinit` before the parameters: the direction, and the key if given (of any
    /// length: the cipher is variable-length to its init, `cipher_hw_rc4_hmac_md5_initkey`).
    pub fn init(&mut self, enc: bool, key: Option<&[u8]>) -> Result<(), Error> {
        self.enc = enc;
        if let Some(key) = key {
            let stream = crate::dit::with(|| sym::rc4(key)).map_err(|_| Error::Cipher)?;
            self.key_len = key.len();
            self.stream = Some(stream);
            self.head = md::context(md::Algorithm::Md5);
            self.tail = self.head.clone_box();
            self.md = self.head.clone_box();
            self.payload = None;
            self.key_set = true;
        }
        Ok(())
    }

    /// `tls_init` (`tls1-aad`): the record's header, whose length a decryption takes the MAC's
    /// length from (written back into `aad`, as the reference writes it). The MAC's length, or
    /// `None` for a header of the wrong length or a record too short for a MAC.
    pub fn tls_init(&mut self, aad: &mut [u8]) -> Option<usize> {
        if aad.len() != TLS1_AAD_LEN {
            return None;
        }
        let (hi, lo) = (*aad.get(TLS1_AAD_LEN - 2)?, *aad.get(TLS1_AAD_LEN - 1)?);
        let mut len = usize::from(hi) << 8 | usize::from(lo);
        if !self.enc {
            len = len.checked_sub(MD5_LEN)?;
            let [h, l] = u16::try_from(len).ok()?.to_be_bytes();
            *aad.get_mut(TLS1_AAD_LEN - 2)? = h;
            *aad.get_mut(TLS1_AAD_LEN - 1)? = l;
        }
        self.payload = Some(len);
        self.md = self.head.clone_box();
        // MD5 of an in-memory buffer doesn't fail.
        let _ = self.md.update(aad);
        Some(MD5_LEN)
    }

    /// `init_mackey` (`mackey`): HMAC-MD5's key, hashed first if longer than a block.
    pub fn set_mac_key(&mut self, key: &[u8]) {
        let mut block = zeroize::Zeroizing::new([0u8; 64]);
        if key.len() > block.len() {
            let mut h = md::context(md::Algorithm::Md5);
            let mut digest = [0u8; MD5_LEN];
            let _ = h.update(key);
            let _ = h.finalize(&mut digest);
            if let Some(b) = block.get_mut(..MD5_LEN) {
                b.copy_from_slice(&digest);
            }
        } else if let Some(b) = block.get_mut(..key.len()) {
            b.copy_from_slice(key);
        }
        for b in block.iter_mut() {
            *b ^= 0x36;
        }
        self.head = md::context(md::Algorithm::Md5);
        let _ = self.head.update(block.as_slice());
        for b in block.iter_mut() {
            *b ^= 0x36 ^ 0x5c;
        }
        self.tail = md::context(md::Algorithm::Md5);
        let _ = self.tail.update(block.as_slice());
    }

    /// The HMAC of what the running hash has absorbed: its inner digest through the outer hash.
    fn hmac(&mut self) -> [u8; MD5_LEN] {
        let mut mac = [0u8; MD5_LEN];
        let _ = self.md.finalize(&mut mac);
        self.md = self.tail.clone_box();
        let _ = self.md.update(&mac);
        let _ = self.md.finalize(&mut mac);
        mac
    }

    /// `cipher_hw_rc4_hmac_md5_cipher` on `data` in place (input in, output out).
    pub fn cipher(&mut self, data: &mut [u8]) -> Result<(), Error> {
        crate::dit::with(|| self.cipher_dit(data))
    }

    fn cipher_dit(&mut self, data: &mut [u8]) -> Result<(), Error> {
        let len = data.len();
        if let Some(plen) = self.payload
            && plen.checked_add(MD5_LEN) != Some(len)
        {
            return Err(Error::Cipher);
        }
        if self.enc {
            let plen = self.payload.unwrap_or(len);
            let _ = self.md.update(data.get(..plen).ok_or(Error::Cipher)?);
            if plen != len {
                let mac = self.hmac();
                data.get_mut(plen..)
                    .ok_or(Error::Cipher)?
                    .copy_from_slice(&mac);
            }
            self.stream.as_mut().ok_or(Error::NoKey)?.apply(data);
        } else {
            self.stream.as_mut().ok_or(Error::NoKey)?.apply(data);
            if let Some(plen) = self.payload {
                let _ = self.md.update(data.get(..plen).ok_or(Error::Cipher)?);
                let mac = self.hmac();
                let got = data.get(plen..).ok_or(Error::Cipher)?;
                // CRYPTO_memcmp.
                let diff = got.iter().zip(&mac).fold(0u8, |a, (x, y)| a | (x ^ y));
                if core::hint::black_box(diff) != 0 {
                    return Err(Error::Cipher);
                }
            } else {
                let _ = self.md.update(data);
            }
        }
        self.payload = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tls_record_round_trips_and_a_bad_mac_fails() {
        let key = [7u8; 16];
        let mac_key = [9u8; 16];
        let payload = b"hello, record";
        let mut header = [0u8; 13];
        header[11] = 0;
        header[12] = u8::try_from(payload.len()).unwrap();

        let mut enc = Ctx::new();
        enc.init(true, Some(&key)).unwrap();
        enc.set_mac_key(&mac_key);
        assert_eq!(enc.tls_init(&mut header.clone()), Some(16));
        let mut record = payload.to_vec();
        record.extend_from_slice(&[0; 16]);
        enc.cipher(&mut record).unwrap();

        let mut dec = Ctx::new();
        dec.init(false, Some(&key)).unwrap();
        dec.set_mac_key(&mac_key);
        let mut dheader = header;
        dheader[12] = u8::try_from(payload.len() + 16).unwrap();
        assert_eq!(dec.tls_init(&mut dheader), Some(16));
        assert_eq!(dheader[12] as usize, payload.len());
        let mut back = record.clone();
        dec.cipher(&mut back).unwrap();
        assert_eq!(&back[..payload.len()], payload);

        let mut bad = Ctx::new();
        bad.init(false, Some(&key)).unwrap();
        bad.set_mac_key(&mac_key);
        let mut bheader = header;
        bheader[12] = u8::try_from(payload.len() + 16).unwrap();
        bad.tls_init(&mut bheader);
        let mut tampered = record;
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(bad.cipher(&mut tampered), Err(Error::Cipher));
    }
}
