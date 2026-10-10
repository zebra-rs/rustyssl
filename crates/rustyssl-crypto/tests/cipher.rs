//! The provider cipher contexts (`provided::cipher`) against vectors from the reference OpenSSL
//! (`tests/data/cipher_vectors.txt`): each mode of each block cipher, triple DES, and ChaCha20
//! (one vector with its counter wrapping), with and without padding, encrypted and decrypted in
//! pieces of every size up to 40 octets; and the provider functions' edges: padding checked
//! for every last octet, `num`, CFB1 counting bits, IV resets, `EVP_Cipher` on partial blocks
//! (docs/DEVIATIONS.md), and the errors each function raises.

#[cfg(test)]
mod tests {
    use rustyssl_crypto::provided::cipher::{Ctx, Error, Kind, Mode};
    use rustyssl_crypto::sym::BlockAlgorithm;

    fn unhex(s: &str) -> Vec<u8> {
        if s == "-" {
            return Vec::new();
        }
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn kind(name: &str) -> Kind {
        if name == "ChaCha20" {
            return Kind::ChaCha20;
        }
        let parts: Vec<&str> = name.split('-').collect();
        let (algorithm, key_len, mode) = match parts[..] {
            ["DES", "EDE3", m] => (BlockAlgorithm::TripleDes, 24, m),
            ["DES", "EDE", m] => (BlockAlgorithm::TripleDes, 16, m),
            ["SM4", m] => (BlockAlgorithm::Sm4, 16, m),
            [a, bits, m] => (
                match a {
                    "AES" => BlockAlgorithm::Aes,
                    "ARIA" => BlockAlgorithm::Aria,
                    "CAMELLIA" => BlockAlgorithm::Camellia,
                    _ => panic!("{name}"),
                },
                bits.parse::<usize>().unwrap() / 8,
                m,
            ),
            _ => panic!("{name}"),
        };
        let mode = match mode {
            "ECB" => Mode::Ecb,
            "CBC" => Mode::Cbc,
            "OFB" => Mode::Ofb,
            "CFB" => Mode::Cfb,
            "CFB1" => Mode::Cfb1,
            "CFB8" => Mode::Cfb8,
            "CTR" => Mode::Ctr,
            _ => panic!("{name}"),
        };
        Kind::Block {
            algorithm,
            key_len,
            mode,
        }
    }

    /// `EVP_EncryptUpdate`'s room: the input plus a block.
    fn room(k: Kind, n: usize) -> usize {
        n + if k.block_size() == 1 {
            0
        } else {
            k.block_size()
        }
    }

    fn run(
        k: Kind,
        enc: bool,
        pad: bool,
        key: &[u8],
        iv: &[u8],
        input: &[u8],
        piece: usize,
    ) -> Vec<u8> {
        let mut ctx = Ctx::new(k);
        let iv = (!iv.is_empty()).then_some(iv);
        ctx.init(enc, Some(key), iv).unwrap();
        ctx.generic_mut().unwrap().set_padding(pad);
        let mut out = Vec::new();
        for chunk in input.chunks(piece.max(1)) {
            let o = ctx
                .update(chunk, chunk.len(), room(k, chunk.len()))
                .unwrap();
            assert_eq!(o.len, o.data.len());
            out.extend_from_slice(&o.data);
        }
        let o = ctx.finalize(room(k, 0)).unwrap();
        out.extend_from_slice(&o.data);
        out
    }

    #[test]
    fn vectors() {
        let text = include_str!("data/cipher_vectors.txt");
        let mut count = 0;
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let f: Vec<&str> = line.split(' ').collect();
            let k = kind(f[0]);
            let pad = f[1] == "1";
            let (key, iv, pt, ct) = (unhex(f[2]), unhex(f[3]), unhex(f[4]), unhex(f[5]));
            for piece in 1..=40 {
                assert_eq!(
                    run(k, true, pad, &key, &iv, &pt, piece),
                    ct,
                    "{line} {piece}"
                );
                assert_eq!(
                    run(k, false, pad, &key, &iv, &ct, piece),
                    pt,
                    "{line} {piece}"
                );
            }
            count += 1;
        }
        assert_eq!(count, 116);
    }

    const AES128_CBC: Kind = Kind::Block {
        algorithm: BlockAlgorithm::Aes,
        key_len: 16,
        mode: Mode::Cbc,
    };

    /// Every last octet of a decrypted block, against a straightforward unpadding.
    #[test]
    fn padding_checks() {
        let key = [7u8; 16];
        for last in 0..=255u8 {
            for fill in [last, 0x10, 0] {
                let mut block = [fill; 16];
                block[15] = last;
                let ct = run(AES128_CBC, true, false, &key, &[0; 16], &block, 16);
                let mut ctx = Ctx::new(AES128_CBC);
                ctx.init(false, Some(&key), Some(&[0; 16])).unwrap();
                let o = ctx.update(&ct, 16, 32).unwrap();
                assert!(o.data.is_empty(), "the block is held back");
                let p = usize::from(last);
                let good = (1..=16).contains(&p) && block[16 - p..].iter().all(|&b| b == last);
                match ctx.finalize(16) {
                    Ok(o) => {
                        assert!(good);
                        assert_eq!(&o.data[..], &block[..16 - p]);
                    }
                    Err(e) => {
                        assert!(!good);
                        assert_eq!(e, Error::BadDecrypt);
                    }
                }
            }
        }
    }

    #[test]
    fn errors() {
        let mut ctx = Ctx::new(AES128_CBC);
        assert_eq!(ctx.update(&[0; 16], 16, 32), Err(Error::NoKeySet));
        assert_eq!(ctx.finalize(16), Err(Error::NoKeySet));
        assert_eq!(
            ctx.init(true, Some(&[0; 15]), None),
            Err(Error::InvalidKeyLength)
        );
        assert_eq!(
            ctx.init(true, None, Some(&[0; 8])),
            Err(Error::InvalidIvLength)
        );
        ctx.init(true, Some(&[0; 16]), Some(&[0; 16])).unwrap();
        assert_eq!(
            ctx.update(&[0; 32], 32, 31),
            Err(Error::OutputBufferTooSmall)
        );
        ctx.generic_mut().unwrap().set_padding(false);
        ctx.update(&[0; 5], 5, 21).unwrap();
        assert_eq!(ctx.finalize(16), Err(Error::WrongFinalBlockLength));
        let g = ctx.generic_mut().unwrap();
        assert_eq!(g.set_num(15), Ok(()));
        assert_eq!(g.set_num(16), Err(Error::FailedToGetParameter));
        assert_eq!(g.set_tls_version(0x0303), Err(Error::FailedToGetParameter));
        let mut ofb = Ctx::new(Kind::Block {
            algorithm: BlockAlgorithm::Aes,
            key_len: 16,
            mode: Mode::Ofb,
        });
        let g = ofb.generic_mut().unwrap();
        assert_eq!(g.set_num(0), Ok(()));
        assert_eq!(
            g.set_num(1),
            Err(Error::FailedToGetParameter),
            "the stream modes' block is 1"
        );
    }

    /// docs/DEVIATIONS.md: `EVP_Cipher` on a partial block processes the whole blocks only.
    #[test]
    fn one_shot_partial_blocks() {
        let key = [3u8; 16];
        let data: Vec<u8> = (0..21).collect();
        let whole = run(AES128_CBC, true, false, &key, &[0; 16], &data[..16], 16);
        for enc in [true, false] {
            let mut ctx = Ctx::new(AES128_CBC);
            ctx.init(enc, Some(&key), Some(&[0; 16])).unwrap();
            let o = ctx.cipher(&data, 21, 37).unwrap();
            assert_eq!(o.len, 21);
            assert_eq!(o.data.len(), 16);
            if enc {
                assert_eq!(&o.data[..], &whole[..]);
            }
        }
    }

    /// docs/DEVIATIONS.md: turning ECB or CBC around without a new key uses the key in the new
    /// direction (OpenSSL keeps the old direction's key schedule).
    #[test]
    fn turning_around_without_a_key() {
        let key = [8u8; 16];
        let data = [0x42u8; 32];
        let ct = run(AES128_CBC, true, false, &key, &[0; 16], &data, 32);
        let mut ctx = Ctx::new(AES128_CBC);
        ctx.init(true, Some(&key), Some(&[0; 16])).unwrap();
        ctx.init(false, None, Some(&[0; 16])).unwrap();
        ctx.generic_mut().unwrap().set_padding(false);
        let mut pt = ctx.update(&ct, 32, 48).unwrap().data.to_vec();
        pt.extend_from_slice(&ctx.finalize(16).unwrap().data);
        assert_eq!(pt, data);
    }

    #[test]
    fn cfb1_counts_bits() {
        let k = Kind::Block {
            algorithm: BlockAlgorithm::Aes,
            key_len: 16,
            mode: Mode::Cfb1,
        };
        let key = [9u8; 16];
        let data = [0xa5u8, 0x3c];
        let octets = run(k, true, true, &key, &[1; 16], &data, 2);
        let mut ctx = Ctx::new(k);
        ctx.init(true, Some(&key), Some(&[1; 16])).unwrap();
        ctx.generic_mut().unwrap().set_use_bits(true);
        assert_eq!(ctx.input_len(13), 2);
        let o = ctx.update(&data, 13, 13).unwrap();
        assert_eq!(o.len, 13);
        assert_eq!(o.last_mask, 0xf8);
        assert_eq!(o.data[0], octets[0]);
        assert_eq!(o.data[1] & 0xf8, octets[1] & 0xf8);
    }

    #[test]
    fn ivs_reset_without_one() {
        let key = [5u8; 16];
        let data = [1u8; 21];
        for mode in [Mode::Cbc, Mode::Cfb, Mode::Cfb8, Mode::Ofb, Mode::Ctr] {
            let k = Kind::Block {
                algorithm: BlockAlgorithm::Aes,
                key_len: 16,
                mode,
            };
            let mut ctx = Ctx::new(k);
            ctx.init(true, Some(&key), Some(&[2; 16])).unwrap();
            let a = ctx.update(&data, 21, 37).unwrap();
            ctx.init(true, None, None).unwrap();
            let b = ctx.update(&data, 21, 37).unwrap();
            // CTR keeps its counter; the others go back to the IV as set.
            assert_eq!(a == b, mode != Mode::Ctr, "{mode:?}");
        }
    }

    #[test]
    fn null_cipher_drops_the_mac() {
        let mut ctx = Ctx::new(Kind::Null);
        ctx.init(false, None, None).unwrap();
        ctx.set_null_mac_size(4);
        assert!(ctx.null_strips_mac());
        let o = ctx.update(&[1; 10], 10, 10).unwrap();
        assert_eq!(o.len, 6);
        assert_eq!(ctx.update(&[1; 3], 3, 3), Err(Error::Silent));
        // `dinit` doesn't change the direction: encrypting stays encrypting.
        ctx.init(true, None, None).unwrap();
        ctx.init(false, None, None).unwrap();
        assert!(!ctx.null_strips_mac());
    }

    #[test]
    fn copies_go_on_the_same() {
        for k in [AES128_CBC, Kind::ChaCha20] {
            let key = [4u8; 32];
            let mut ctx = Ctx::new(k);
            ctx.init(true, Some(&key[..k.key_len()]), Some(&[6; 16]))
                .unwrap();
            ctx.update(&[0; 21], 21, 37).unwrap();
            let mut copy = ctx.clone();
            assert_eq!(ctx.update(&[0; 30], 30, 46), copy.update(&[0; 30], 30, 46));
        }
    }
}
