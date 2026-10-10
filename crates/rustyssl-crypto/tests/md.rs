//! Digests against vectors from the reference OpenSSL (`tests/data/md_vectors.txt`): every
//! algorithm over four messages, fed in pieces of several sizes; XOFs also squeezed in pieces;
//! and the context's life cycle (copy, reset, finalizing twice, wrong sizes).

#[cfg(test)]
mod tests {
    use rustyssl_crypto::md::{self, Algorithm, Error};

    fn algorithm(name: &str) -> Algorithm {
        match name {
            "SHA1" => Algorithm::Sha1,
            "SHA224" => Algorithm::Sha224,
            "SHA256" => Algorithm::Sha256,
            "SHA384" => Algorithm::Sha384,
            "SHA512" => Algorithm::Sha512,
            "SHA512-224" => Algorithm::Sha512_224,
            "SHA512-256" => Algorithm::Sha512_256,
            "SHA3-224" => Algorithm::Sha3_224,
            "SHA3-256" => Algorithm::Sha3_256,
            "SHA3-384" => Algorithm::Sha3_384,
            "SHA3-512" => Algorithm::Sha3_512,
            "SHAKE128" => Algorithm::Shake128,
            "SHAKE256" => Algorithm::Shake256,
            "KECCAK-KMAC-128" => Algorithm::KeccakKmac128,
            "KECCAK-KMAC-256" => Algorithm::KeccakKmac256,
            "MD5" => Algorithm::Md5,
            "MD5-SHA1" => Algorithm::Md5Sha1,
            "SM3" => Algorithm::Sm3,
            "BLAKE2S-256" => Algorithm::Blake2s256,
            "BLAKE2B-512" => Algorithm::Blake2b512,
            "RIPEMD160" => Algorithm::Ripemd160,
            "MD4" => Algorithm::Md4,
            "WHIRLPOOL" => Algorithm::Whirlpool,
            other => panic!("unknown algorithm {other}"),
        }
    }

    fn message(n: u32) -> Vec<u8> {
        match n {
            0 => Vec::new(),
            1 => b"abc".to_vec(),
            2 => vec![0xa3; 200],
            _ => (0..1000u32)
                .map(|i| u8::try_from((i * 7 + 3) % 256).unwrap())
                .collect(),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Every algorithm's digest of every message, fed in pieces of `piece` octets.
    fn digests(piece: usize) -> usize {
        let mut checked = 0;
        for line in include_str!("data/md_vectors.txt")
            .lines()
            .filter(|l| !l.starts_with('#'))
        {
            let mut parts = line.split(' ');
            let (name, msg, want) = (
                parts.next().unwrap(),
                parts.next().unwrap(),
                parts.next().unwrap(),
            );
            let alg = algorithm(name);
            let data = message(msg.parse().unwrap());
            let mut ctx = md::context(alg);
            for chunk in data.chunks(piece) {
                ctx.update(chunk).unwrap();
            }
            let size = if alg.is_xof() { 300 } else { alg.output_size() };
            let mut out = vec![0u8; size];
            ctx.finalize(&mut out).unwrap();
            assert_eq!(
                hex(&out),
                want,
                "{name} of message {msg} in pieces of {piece}"
            );
            if alg.is_xof() {
                let mut ctx = md::context(alg);
                ctx.update(&data).unwrap();
                let mut squeezed = Vec::new();
                for n in [1, 167, 1, 131] {
                    let mut part = vec![0u8; n];
                    ctx.squeeze(&mut part).unwrap();
                    squeezed.extend(part);
                }
                assert_eq!(
                    hex(&squeezed),
                    want,
                    "{name} of message {msg} squeezed in pieces"
                );
            }
            checked += 1;
        }
        checked
    }

    #[test]
    fn vectors_from_the_reference() {
        for piece in [1, 7, 64, 135, 1000] {
            assert_eq!(digests(piece), 92);
        }
    }

    #[test]
    fn life_cycle() {
        for alg in Algorithm::ALL {
            let mut ctx = md::context(alg);
            ctx.update(b"hello ").unwrap();
            let mut copy = ctx.clone_box();
            ctx.update(b"world").unwrap();
            copy.update(b"world").unwrap();
            let size = alg.output_size();
            let (mut a, mut b) = (vec![0u8; size], vec![0u8; size]);
            ctx.finalize(&mut a).unwrap();
            copy.finalize(&mut b).unwrap();
            assert_eq!(a, b, "{alg:?}: a copy carries on the same");
            assert_eq!(ctx.update(b"x"), Err(Error::Finalized));
            assert_eq!(ctx.finalize(&mut a), Err(Error::Finalized));
            ctx.reset();
            ctx.update(b"hello world").unwrap();
            ctx.finalize(&mut b).unwrap();
            assert_eq!(a, b, "{alg:?}: reset starts again");
            if !alg.is_xof() {
                let mut ctx = md::context(alg);
                assert_eq!(
                    ctx.finalize(&mut vec![0u8; size + 1]),
                    Err(Error::OutputSize)
                );
                assert_eq!(ctx.squeeze(&mut [0u8; 4]), Err(Error::NotXof));
            }
        }
    }
}
