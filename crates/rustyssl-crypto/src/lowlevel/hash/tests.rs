#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test arithmetic on small known values"
)]

use digest::Digest;

use super::*;

/// The message the tests hash: `(i * 7 + 3) mod 256`.
fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

/// Feeds `msg` to `update` in pieces of `piece` (all at once for 0).
fn in_pieces(msg: &[u8], piece: usize, mut update: impl FnMut(&[u8])) {
    if piece == 0 {
        update(msg);
    } else {
        for chunk in msg.chunks(piece) {
            update(chunk);
        }
    }
}

const LENGTHS: [usize; 14] = [0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 300, 1000];
const PIECES: [usize; 5] = [0, 1, 7, 64, 129];

fn md32_digest(
    kind: Md32Kind,
    init: fn() -> Md32,
    size: usize,
    msg: &[u8],
    piece: usize,
) -> Vec<u8> {
    let mut c = init();
    in_pieces(msg, piece, |d| c.update(kind, d).unwrap());
    c.finish(kind).unwrap();
    assert_eq!(c.num, 0);
    assert_eq!(c.data, [0; MD32_BLOCK]);
    let mut out = vec![0; size];
    c.output(kind, &mut out);
    out
}

#[test]
fn md32_hashes_match_the_crates() {
    for len in LENGTHS {
        let msg = message(len);
        for piece in PIECES {
            assert_eq!(
                md32_digest(Md32Kind::Md4, Md32::md4, 16, &msg, piece),
                md4::Md4::digest(&msg).to_vec()
            );
            assert_eq!(
                md32_digest(Md32Kind::Md5, Md32::md5, 16, &msg, piece),
                md5::Md5::digest(&msg).to_vec()
            );
            assert_eq!(
                md32_digest(Md32Kind::Ripemd160, Md32::ripemd160, 20, &msg, piece),
                ripemd::Ripemd160::digest(&msg).to_vec()
            );
            assert_eq!(
                md32_digest(Md32Kind::Sha1, Md32::sha1, 20, &msg, piece),
                sha1::Sha1::digest(&msg).to_vec()
            );
            assert_eq!(
                md32_digest(Md32Kind::Sha256, Md32::sha224, 28, &msg, piece),
                sha2::Sha224::digest(&msg).to_vec()
            );
            assert_eq!(
                md32_digest(Md32Kind::Sha256, Md32::sha256, 32, &msg, piece),
                sha2::Sha256::digest(&msg).to_vec()
            );
        }
    }
}

#[test]
fn md32_counts_bits_and_buffers_like_openssl() {
    let mut c = Md32::sha256();
    c.nl = 0xffff_fff0;
    c.update(Md32Kind::Sha256, &[1, 2, 3]).unwrap();
    assert_eq!((c.nl, c.nh, c.num), (0x0000_0008, 1, 3));
    assert_eq!(&c.data[..4], &[1, 2, 3, 0]);
    // A filled buffer is compressed and zeroed before the rest is buffered.
    c.update(Md32Kind::Sha256, &[9; 70]).unwrap();
    assert_eq!(c.num, 9);
    assert_eq!(&c.data[..10], &[9, 9, 9, 9, 9, 9, 9, 9, 9, 0]);
}

#[test]
fn corrupt_counts_are_refused() {
    let mut c = Md32::md5();
    c.num = 64;
    assert_eq!(c.update(Md32Kind::Md5, b"x"), Err(Error::Corrupt));
    assert_eq!(c.finish(Md32Kind::Md5), Err(Error::Corrupt));
    // No input is fine, as in OpenSSL, whatever the count.
    assert_eq!(c.update(Md32Kind::Md5, b""), Ok(()));
    let mut s = Sha512 {
        h: [0; 8],
        nl: 0,
        nh: 0,
        data: [0; SHA512_BLOCK],
        num: 128,
    };
    assert_eq!(s.update(b"x"), Err(Error::Corrupt));
    assert_eq!(s.finish(), Err(Error::Corrupt));
    let mut m = Mdc2 {
        num: 8,
        data: [0; 8],
        h: [0; 8],
        hh: [0; 8],
        pad_type: 2,
    };
    assert_eq!(m.update(b"x"), Err(Error::Corrupt));
    assert_eq!(m.finish(), Err(Error::Corrupt));
    assert_eq!(m.update(b""), Ok(()));
    let mut w = Whirlpool::new();
    w.bitoff = 512;
    assert_eq!(w.bit_update(b"x", 8), Err(Error::Corrupt));
    assert_eq!(w.finish(), Err(Error::Corrupt));
    assert_eq!(w.bit_update(b"", 0), Ok(()));
    assert_eq!(Whirlpool::new().bit_update(b"x", 9), Err(Error::Input));
}

#[test]
fn output_lengths() {
    assert_eq!(sha256_output_len(32), Some(32));
    assert_eq!(sha256_output_len(28), Some(28));
    assert_eq!(sha256_output_len(23), Some(20));
    assert_eq!(sha256_output_len(33), None);
    assert_eq!(sha512_output_len(28), Some(28));
    assert_eq!(sha512_output_len(20), None);
}

#[test]
fn sha512_matches_the_crate_and_keeps_its_count() {
    for len in LENGTHS {
        let msg = message(len);
        for piece in PIECES {
            for (init, md_len) in [
                (Sha512::init_sha384 as fn(&mut Sha512), 48),
                (Sha512::init_sha512, 64),
            ] {
                let mut c = Sha512 {
                    h: [0; 8],
                    nl: 0,
                    nh: 0,
                    data: [0xa5; SHA512_BLOCK],
                    num: 0,
                };
                init(&mut c);
                in_pieces(&msg, piece, |d| c.update(d).unwrap());
                let num = c.num;
                c.finish().unwrap();
                assert_eq!(c.num, num);
                let mut out = vec![0; sha512_output_len(md_len).unwrap()];
                c.output(&mut out);
                let want = if md_len == 48 {
                    sha2::Sha384::digest(&msg).to_vec()
                } else {
                    sha2::Sha512::digest(&msg).to_vec()
                };
                assert_eq!(out, want);
            }
        }
    }
}

/// MDC2's known answers, from OpenSSL's test/mdc2test.c.
#[test]
fn mdc2_known_answers() {
    let msg = b"Now is the time for all ";
    let mut c = Mdc2 {
        num: 0,
        data: [0; 8],
        h: [0; 8],
        hh: [0; 8],
        pad_type: 0,
    };
    c.init();
    c.update(msg).unwrap();
    assert_eq!(
        hex(&c.finish().unwrap()),
        "42e50cd224baceba760bdd2bd409281a"
    );
    c.init();
    c.pad_type = 2;
    c.update(msg).unwrap();
    assert_eq!(
        hex(&c.finish().unwrap()),
        "2e4679b5add9ca7535d87afeab33bee2"
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn whirlpool_bytes(msg: &[u8], piece: usize) -> [u8; 64] {
    let mut c = Whirlpool::new();
    in_pieces(msg, piece, |d| c.bit_update(d, d.len() * 8).unwrap());
    c.finish().unwrap();
    c.h
}

#[test]
fn whirlpool_matches_the_crate() {
    for len in LENGTHS {
        let msg = message(len);
        for piece in PIECES {
            assert_eq!(
                whirlpool_bytes(&msg, piece).to_vec(),
                whirlpool::Whirlpool::digest(&msg).to_vec()
            );
        }
    }
}

/// Appends the low `bits` bits of `bytes` (big-endian) to a bit string.
fn push_bits(out: &mut Vec<bool>, bytes: &[u8], bits: usize) {
    let all: Vec<bool> = bytes
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| b >> i & 1 == 1))
        .collect();
    out.extend_from_slice(&all[all.len() - bits..]);
}

/// Hashes a bit string whose length is a multiple of 8 through whole octets.
fn whirlpool_of_bits(bits: &[bool]) -> [u8; 64] {
    assert_eq!(bits.len() % 8, 0);
    let bytes: Vec<u8> = bits
        .chunks(8)
        .map(|c| c.iter().fold(0u8, |a, &b| a << 1 | b as u8))
        .collect();
    whirlpool_bytes(&bytes, 0)
}

/// Bit updates append bits, including the split where OpenSSL's last step runs past the block
/// (505 bits, then 8: OpenSSL keeps 513 bits and writes past its buffer).
#[test]
fn whirlpool_bit_updates_append_bits() {
    let msg = message(400);
    // Splits into bit counts, ending on a whole octet so the result can be checked by octets.
    let splits: [&[usize]; 7] = [
        &[3, 5, 8, 16, 1000, 7, 1],
        &[1; 16],
        &[505, 7],
        &[505, 8, 7],
        &[505, 3, 8, 4],
        &[511, 1, 513, 7],
        &[9, 9, 9, 9, 9, 9, 9, 1, 1000, 4, 4],
    ];
    for split in splits {
        let mut c = Whirlpool::new();
        let mut want = Vec::new();
        let mut at = 0;
        for &bits in split {
            let n = bits.div_ceil(8);
            let bytes = &msg[at..at + n];
            at += n;
            c.bit_update(bytes, bits).unwrap();
            assert!(c.bitoff < 512, "{split:?}");
            push_bits(&mut want, bytes, bits);
        }
        assert_eq!(usize::try_from(c.bitlen[0]).unwrap(), want.len());
        c.finish().unwrap();
        assert_eq!(c.h, whirlpool_of_bits(&want), "{split:?}");
    }
}

fn md2_hex(input: &[u8], pieces: usize) -> String {
    let mut c = Md2::default();
    c.init();
    let step = input.len() / pieces.max(1) + 1;
    for chunk in input.chunks(step) {
        c.update(chunk).unwrap();
    }
    c.finish().unwrap().iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn md2_matches_rfc_1319() {
    // RFC 1319, A.5.
    let vectors = [
        ("", "8350e5a3e24c153df2275c9f80692773"),
        ("a", "32ec01ec4a6dac72c0ab96fb34c0b5d1"),
        ("abc", "da853b0d3f88d99b30283a69e6ded6bb"),
        ("message digest", "ab4f496bfb2a530b219ff33031fe06b0"),
        ("abcdefghijklmnopqrstuvwxyz", "4e8ddff3650292ab5a4108c3aa47940b"),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "d5976f79d83d3a0dc9806c3c66f3efd8",
        ),
    ];
    for (input, want) in vectors {
        assert_eq!(md2_hex(input.as_bytes(), 1), want, "{input:?}");
    }
}

#[test]
fn md2_matches_the_md2_crate_in_pieces() {
    let msg: Vec<u8> = (0..200u8).collect();
    for len in [0, 1, 15, 16, 17, 31, 32, 33, 100, 200] {
        let want: String = md2::Md2::digest(&msg[..len]).iter().map(|b| format!("{b:02x}")).collect();
        for pieces in [1, 2, 3, 7] {
            assert_eq!(md2_hex(&msg[..len], pieces), want, "{len} in {pieces}");
        }
    }
    let mut c = Md2 { num: 16, ..Md2::default() };
    assert_eq!(c.update(b"x"), Err(Error::Corrupt));
}
