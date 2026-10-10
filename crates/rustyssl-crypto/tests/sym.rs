//! Symmetric primitives against vectors from the reference OpenSSL (`tests/data/sym_vectors.txt`):
//! every block cipher in ECB over three blocks (with the key lengths OpenSSL accepts at their
//! edges, and RC2's effective lengths), RC4 and ChaCha20 over 300 octets (ChaCha20's counter
//! carrying across its first word), Poly1305 MACs, and AES-128-GCM assembled here from AES and
//! GHASH; POLYVAL against RFC 8452's example; and copies of key streams mid-stream.

#[cfg(test)]
mod tests {
    use rustyssl_crypto::sym::{self, BlockAlgorithm, HashAlgorithm};

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn pattern(n: usize, mul: u32, add: u32) -> Vec<u8> {
        (0..u32::try_from(n).unwrap())
            .map(|i| u8::try_from((i * mul + add) % 256).unwrap())
            .collect()
    }

    fn block(name: &str) -> Option<BlockAlgorithm> {
        Some(match name {
            n if n.starts_with("AES-") && n.ends_with("-ECB") => BlockAlgorithm::Aes,
            n if n.starts_with("ARIA-") => BlockAlgorithm::Aria,
            n if n.starts_with("CAMELLIA-") => BlockAlgorithm::Camellia,
            "SM4-ECB" => BlockAlgorithm::Sm4,
            "DES-ECB" => BlockAlgorithm::Des,
            "DES-EDE-ECB" | "DES-EDE3-ECB" => BlockAlgorithm::TripleDes,
            "BF-ECB" => BlockAlgorithm::Blowfish,
            "CAST5-ECB" => BlockAlgorithm::Cast5,
            "IDEA-ECB" => BlockAlgorithm::Idea,
            "RC2-ECB" => BlockAlgorithm::Rc2,
            _ => return None,
        })
    }

    #[test]
    fn vectors_from_the_reference() {
        let key = pattern(300, 13, 5);
        let data = pattern(300, 7, 3);
        let mut checked = 0;
        for line in include_str!("data/sym_vectors.txt")
            .lines()
            .filter(|l| !l.starts_with('#'))
        {
            let f: Vec<&str> = line.split(' ').collect();
            let (name, klen, bits, iv, want) =
                (f[0], f[1].parse::<usize>().unwrap(), f[2], f[3], f[4]);
            let got = if let Some(alg) = block(name) {
                let rc2 = (bits != "0").then(|| bits.parse().unwrap());
                let c = sym::block_cipher(alg, &key[..klen], rc2).unwrap();
                let mut buf = data[..48].to_vec();
                c.encrypt_blocks(&mut buf).unwrap();
                let mut back = buf.clone();
                c.decrypt_blocks(&mut back).unwrap();
                assert_eq!(back, data[..48], "{name} {klen} decrypts back");
                buf
            } else if name == "RC4" || name == "ChaCha20" {
                let mut s = if name == "RC4" {
                    sym::rc4(&key[..klen]).unwrap()
                } else {
                    sym::chacha20(&key[..32], &unhex(iv)).unwrap()
                };
                let mut buf = data.clone();
                s.apply(&mut buf[..100]);
                // A copy mid-stream carries on the same.
                let mut copy = s.clone_box().unwrap();
                let mut rest = buf[100..].to_vec();
                s.apply(&mut buf[100..]);
                copy.apply(&mut rest);
                assert_eq!(rest, buf[100..], "{name}: a copy carries on the same");
                buf
            } else if name == "POLY1305" {
                let mut u = sym::universal_hash(HashAlgorithm::Poly1305, &key[..32]).unwrap();
                let whole = klen / 16 * 16;
                u.update_padded(&data[..whole]);
                u.finalize(&data[whole..klen]).to_vec()
            } else if name == "AES-128-GCM" {
                gcm(&key[..16], &unhex(iv), &data[200..220], &data[..50])
            } else {
                panic!("unknown {name}");
            };
            assert_eq!(hex(&got), want, "{name} key {klen} bits {bits}");
            checked += 1;
        }
        assert_eq!(checked, 45);
    }

    /// AES-GCM with a 12-octet IV, from the AES block cipher and GHASH: the ciphertext, then
    /// the tag.
    fn gcm(key: &[u8], iv: &[u8], aad: &[u8], plain: &[u8]) -> Vec<u8> {
        let aes = sym::block_cipher(BlockAlgorithm::Aes, key, None).unwrap();
        let mut h = [0u8; 16];
        aes.encrypt_blocks(&mut h).unwrap();
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        let mut out = plain.to_vec();
        for (n, chunk) in out.chunks_mut(16).enumerate() {
            let mut ctr = j0;
            ctr[12..].copy_from_slice(&(2 + u32::try_from(n).unwrap()).to_be_bytes());
            aes.encrypt_blocks(&mut ctr).unwrap();
            chunk.iter_mut().zip(ctr).for_each(|(b, k)| *b ^= k);
        }
        let mut g = sym::universal_hash(HashAlgorithm::Ghash, &h).unwrap();
        g.update_padded(aad);
        g.update_padded(&out);
        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&(aad.len() as u64 * 8).to_be_bytes());
        lengths[8..].copy_from_slice(&(out.len() as u64 * 8).to_be_bytes());
        let s = g.finalize(&lengths);
        let mut ek = j0;
        aes.encrypt_blocks(&mut ek).unwrap();
        out.extend(s.iter().zip(ek).map(|(a, b)| a ^ b));
        out
    }

    #[test]
    fn polyval_rfc_8452() {
        let mut p = sym::universal_hash(
            HashAlgorithm::Polyval,
            &unhex("25629347589242761d31f826ba4b757b"),
        )
        .unwrap();
        p.update_padded(&unhex("4f4f95668c83dfb6401762bb2d01a262"));
        let tag = p.finalize(&unhex("d1a24ddd2721d006bbe45f20d3c9f362"));
        assert_eq!(hex(&tag), "f7a3b47b846119fae5b7866cf5e5b77e");
    }

    #[test]
    fn refusals() {
        assert!(sym::block_cipher(BlockAlgorithm::Aes, &[0; 17], None).is_err());
        assert!(sym::block_cipher(BlockAlgorithm::Blowfish, &[0; 73], None).is_err());
        assert!(sym::block_cipher(BlockAlgorithm::Cast5, &[], None).is_err());
        assert!(sym::block_cipher(BlockAlgorithm::Rc2, &[0; 16], Some(1025)).is_err());
        assert!(sym::rc4(&[]).is_err());
        assert!(sym::chacha20(&[0; 32], &[0; 12]).is_err());
        let c = sym::block_cipher(BlockAlgorithm::Des, &[1; 8], None).unwrap();
        assert!(c.encrypt_blocks(&mut [0; 12]).is_err());
    }
}
