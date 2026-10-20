//! Header protection for `rustyssl-tls`'s test provider, through `rustyssl-crypto` directly, so
//! the crate's tests and fuzz targets run with no C.

use rustyssl_crypto::sym::{BlockAlgorithm, BlockCipher, block_cipher, chacha20};
use rustyssl_tls::error::{Error, Result};

pub use rustyssl_tls::testprov::TestProvider;

use crate::crypto::{HeaderProtection, HpAlg, Provider};

enum Hp {
    Aes(Box<dyn BlockCipher>),
    ChaCha([u8; 32]),
}

impl HeaderProtection for Hp {
    fn mask(&self, sample: &[u8; 16]) -> Result<[u8; 5]> {
        let mut block = *sample;
        match self {
            Self::Aes(c) => c.encrypt_blocks(&mut block).map_err(|_| Error::internal())?,
            Self::ChaCha(key) => {
                // RFC 9001, section 5.4.4: the sample's first four octets are the block
                // counter and the rest the nonce, the same words as OpenSSL's 16-octet IV.
                let mut s = chacha20(key, sample).map_err(|_| Error::internal())?;
                block = [0; 16];
                s.apply(&mut block);
            }
        }
        let [a, b, c, d, e, ..] = block;
        Ok([a, b, c, d, e])
    }
}

impl Provider for TestProvider {
    fn header_protection(&self, alg: HpAlg, key: &[u8]) -> Result<Box<dyn HeaderProtection>> {
        if key.len() != alg.key_len() {
            return Err(Error::internal());
        }
        Ok(Box::new(match alg {
            HpAlg::Aes128 | HpAlg::Aes256 => Hp::Aes(
                block_cipher(BlockAlgorithm::Aes, key, None).map_err(|_| Error::internal())?,
            ),
            HpAlg::ChaCha20 => Hp::ChaCha(key.try_into().map_err(|_| Error::internal())?),
        }))
    }
}
