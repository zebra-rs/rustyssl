//! The deprecated `AES_*` functions' key schedules and block functions (`AES_set_encrypt_key(3)`).
//!
//! An `AES_KEY` holds the expanded key schedule itself, so the block functions run from a
//! schedule, not a key: the `aes` crate's round functions (constant time: AES-NI, the ARMv8
//! instructions, or its fixsliced software AES) with each round key in turn. A decryption
//! schedule is OpenSSL's: the encryption schedule's round keys in reverse order, the inner ones
//! through InvMixColumns, for the equivalent inverse cipher.
//!
//! [`Schedule`] keeps the round keys as octets in FIPS 197 order; how they're laid out in the
//! `AES_KEY`'s words is the platform's business (the FFI layer's).

use aes::Block;
use aes::hazmat::{cipher_round, equiv_inv_cipher_round, inv_mix_columns, mix_columns};
use zeroize::Zeroize;

/// The most rounds, AES-256's.
pub const MAX_ROUNDS: usize = 14;

/// Why a key couldn't be set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A key size other than 128, 192, or 256 bits (`AES_set_encrypt_key` returns -2).
    Bits,
}

/// An expanded key schedule: `rounds + 1` round keys of 16 octets each.
#[derive(Clone, PartialEq, Eq)]
pub struct Schedule {
    /// The round keys, in the order the block function uses them.
    pub keys: [[u8; 16]; MAX_ROUNDS + 1],
    /// 10, 12, or 14.
    pub rounds: usize,
}

impl core::fmt::Debug for Schedule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Schedule")
            .field("rounds", &self.rounds)
            .finish_non_exhaustive()
    }
}

impl Drop for Schedule {
    fn drop(&mut self) {
        self.keys.zeroize();
    }
}

/// SubBytes of each octet of `word`, constant time: the word as a block's first column through
/// a cipher round with a zero round key, then InvMixColumns to undo MixColumns, leaves its
/// substituted octets where ShiftRows moved them (rows 0 to 3 of column 0 go to octets 0, 13,
/// 10, and 7).
fn sub_word(word: [u8; 4]) -> [u8; 4] {
    let mut block = Block::default();
    for (b, w) in block.iter_mut().zip(word) {
        *b = w;
    }
    cipher_round(&mut block, &Block::default());
    inv_mix_columns(&mut block);
    let at = |i: usize| block.get(i).copied().unwrap_or(0);
    let out = [at(0), at(13), at(10), at(7)];
    block.as_mut_slice().zeroize();
    out
}

/// The encryption schedule of `key` (FIPS 197's KeyExpansion), or [`Error::Bits`] for a key of
/// another size than 16, 24, or 32 octets.
pub fn encrypt_schedule(key: &[u8]) -> Result<Schedule, Error> {
    crate::dit::with(|| {
        let (nk, rounds): (usize, usize) = match key.len() {
            16 => (4, 10),
            24 => (6, 12),
            32 => (8, 14),
            _ => return Err(Error::Bits),
        };
        let total = rounds.saturating_add(1).saturating_mul(4);
        let mut words = [[0u8; 4]; 4 * (MAX_ROUNDS + 1)];
        for (w, k) in words.iter_mut().zip(key.as_chunks::<4>().0) {
            *w = *k;
        }
        let mut rcon: u8 = 1;
        for i in nk..total {
            let mut temp = words.get(i.wrapping_sub(1)).copied().unwrap_or_default();
            let pos = i.checked_rem(nk).unwrap_or(1);
            if pos == 0 {
                temp.rotate_left(1);
                temp = sub_word(temp);
                temp[0] ^= rcon;
                rcon = (rcon << 1) ^ (if rcon & 0x80 != 0 { 0x1b } else { 0 });
            } else if nk > 6 && pos == 4 {
                temp = sub_word(temp);
            }
            let back = words.get(i.wrapping_sub(nk)).copied().unwrap_or_default();
            if let Some(w) = words.get_mut(i) {
                for ((d, a), b) in w.iter_mut().zip(back).zip(temp) {
                    *d = a ^ b;
                }
            }
            temp.zeroize();
        }
        let mut schedule = Schedule {
            keys: [[0; 16]; MAX_ROUNDS + 1],
            rounds,
        };
        for (round, four) in schedule.keys.iter_mut().zip(words.as_chunks::<4>().0) {
            for (dst, w) in round.as_chunks_mut::<4>().0.iter_mut().zip(four) {
                *dst = *w;
            }
        }
        words.zeroize();
        Ok(schedule)
    })
}

/// The decryption schedule of `key`: the encryption schedule's round keys in reverse order,
/// the inner ones through InvMixColumns.
pub fn decrypt_schedule(key: &[u8]) -> Result<Schedule, Error> {
    crate::dit::with(|| {
        let enc = encrypt_schedule(key)?;
        let rounds = enc.rounds;
        let mut dec = Schedule {
            keys: [[0; 16]; MAX_ROUNDS + 1],
            rounds,
        };
        for (r, dst) in dec
            .keys
            .iter_mut()
            .take(rounds.saturating_add(1))
            .enumerate()
        {
            let src = enc
                .keys
                .get(rounds.wrapping_sub(r))
                .copied()
                .unwrap_or_default();
            let mut block = Block::from(src);
            if r != 0 && r != rounds {
                inv_mix_columns(&mut block);
            }
            for (d, b) in dst.iter_mut().zip(block.iter()) {
                *d = *b;
            }
            block.as_mut_slice().zeroize();
        }
        Ok(dec)
    })
}

/// XORs a round key into the state.
fn add_round_key(state: &mut Block, key: &[u8; 16]) {
    for (s, k) in state.iter_mut().zip(key) {
        *s ^= k;
    }
}

impl Schedule {
    /// The round key for round `r`.
    fn key(&self, r: usize) -> [u8; 16] {
        self.keys.get(r).copied().unwrap_or_default()
    }

    /// Encrypts one block with an encryption schedule (`AES_encrypt`).
    pub fn encrypt(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut state = Block::from(*block);
        add_round_key(&mut state, &self.key(0));
        for r in 1..self.rounds {
            let mut k = Block::from(self.key(r));
            cipher_round(&mut state, &k);
            k.as_mut_slice().zeroize();
        }
        // The last round has no MixColumns: undo the one the round function does.
        cipher_round(&mut state, &Block::default());
        inv_mix_columns(&mut state);
        add_round_key(&mut state, &self.key(self.rounds));
        let out: [u8; 16] = state.into();
        out
    }

    /// Decrypts one block with a decryption schedule (`AES_decrypt`).
    pub fn decrypt(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut state = Block::from(*block);
        add_round_key(&mut state, &self.key(0));
        for r in 1..self.rounds {
            let mut k = Block::from(self.key(r));
            equiv_inv_cipher_round(&mut state, &k);
            k.as_mut_slice().zeroize();
        }
        // The last round has no InvMixColumns: undo the one the round function does.
        equiv_inv_cipher_round(&mut state, &Block::default());
        mix_columns(&mut state);
        add_round_key(&mut state, &self.key(self.rounds));
        let out: [u8; 16] = state.into();
        out
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "test octets from small counters"
)]
mod tests {
    use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// FIPS 197 Appendix A.1: AES-128's key expansion, first and last round keys.
    #[test]
    fn fips197_key_expansion() {
        let key: Vec<u8> = (0..16)
            .map(|i| {
                [
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
                    0xcf, 0x4f, 0x3c,
                ][i]
            })
            .collect();
        let s = encrypt_schedule(&key).unwrap();
        assert_eq!(s.rounds, 10);
        assert_eq!(hex(&s.keys[1]), "a0fafe1788542cb123a339392a6c7605");
        assert_eq!(hex(&s.keys[10]), "d014f9a8c9ee2589e13f0cc8b6630ca6");
        assert_eq!(encrypt_schedule(&[0; 20]), Err(Error::Bits));
    }

    /// Encryption and decryption match the `aes` crate for each key size.
    #[test]
    fn blocks_match_the_crate() {
        for len in [16usize, 24, 32] {
            let key: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let enc = encrypt_schedule(&key).unwrap();
            let dec = decrypt_schedule(&key).unwrap();
            for seed in 0..20u8 {
                let block: [u8; 16] =
                    core::array::from_fn(|i| seed.wrapping_mul(31).wrapping_add(i as u8));
                let mut want = Block::from(block);
                match len {
                    16 => aes::Aes128::new_from_slice(&key)
                        .unwrap()
                        .encrypt_block(&mut want),
                    24 => aes::Aes192::new_from_slice(&key)
                        .unwrap()
                        .encrypt_block(&mut want),
                    _ => aes::Aes256::new_from_slice(&key)
                        .unwrap()
                        .encrypt_block(&mut want),
                }
                let got = enc.encrypt(&block);
                assert_eq!(got.as_slice(), want.as_slice());
                assert_eq!(dec.decrypt(&got), block);
                let mut back = want;
                match len {
                    16 => aes::Aes128::new_from_slice(&key)
                        .unwrap()
                        .decrypt_block(&mut back),
                    24 => aes::Aes192::new_from_slice(&key)
                        .unwrap()
                        .decrypt_block(&mut back),
                    _ => aes::Aes256::new_from_slice(&key)
                        .unwrap()
                        .decrypt_block(&mut back),
                }
                assert_eq!(back.as_slice(), block.as_slice());
            }
        }
    }
}
