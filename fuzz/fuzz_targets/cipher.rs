//! Fuzzes the provider cipher contexts with arbitrary operations: the first octets pick the
//! cipher, the direction, padding, and CFB1's bits, and the rest is a script of updates (of
//! lengths read from it, over its own octets as data), finals, `cipher` calls, `num` sets, and
//! re-inits. Nothing may panic, every output must fit the room it was given, and decrypting
//! what the same steps encrypted (padding on, whole updates) must give the input back.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_crypto::provided::cipher::{Ctx, Kind, Mode};
use rustyssl_crypto::sym::BlockAlgorithm;

const KINDS: [Kind; 10] = [
    Kind::Block {
        algorithm: BlockAlgorithm::Aes,
        key_len: 16,
        mode: Mode::Cbc,
    },
    Kind::Block {
        algorithm: BlockAlgorithm::Aes,
        key_len: 32,
        mode: Mode::Ecb,
    },
    Kind::Block {
        algorithm: BlockAlgorithm::Aes,
        key_len: 16,
        mode: Mode::Ofb,
    },
    Kind::Block {
        algorithm: BlockAlgorithm::Aes,
        key_len: 24,
        mode: Mode::Cfb,
    },
    Kind::Block {
        algorithm: BlockAlgorithm::Aes,
        key_len: 16,
        mode: Mode::Cfb1,
    },
    Kind::Block {
        algorithm: BlockAlgorithm::Camellia,
        key_len: 16,
        mode: Mode::Cfb8,
    },
    Kind::Block {
        algorithm: BlockAlgorithm::Aria,
        key_len: 16,
        mode: Mode::Ctr,
    },
    Kind::Block {
        algorithm: BlockAlgorithm::TripleDes,
        key_len: 24,
        mode: Mode::Cbc,
    },
    Kind::Block {
        algorithm: BlockAlgorithm::TripleDes,
        key_len: 16,
        mode: Mode::Cfb1,
    },
    Kind::ChaCha20,
];

fn room(k: Kind, n: usize) -> usize {
    n + if k.block_size() == 1 {
        0
    } else {
        k.block_size()
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&head, script)) = data.split_first() else {
        return;
    };
    let kind = KINDS[usize::from(head) % KINDS.len()];
    let key = [0x5au8; 32];
    let iv = [0xa5u8; 16];
    let iv = (kind.iv_len() > 0).then_some(&iv[..kind.iv_len()]);
    let key = &key[..kind.key_len()];

    // A script of arbitrary steps on one context: no panics, outputs within their room.
    let mut ctx = Ctx::new(kind);
    let _ = ctx.init(head & 0x10 != 0, Some(key), iv);
    if let Some(g) = ctx.generic_mut() {
        g.set_padding(head & 0x20 != 0);
        g.set_use_bits(head & 0x40 != 0);
    }
    let mut rest = script;
    while let Some((&op, tail)) = rest.split_first() {
        let len = usize::from(tail.first().copied().unwrap_or(0));
        let input = &tail[..len.min(tail.len())];
        let inl = input.len();
        let n = ctx.input_len(inl).min(inl);
        let input = &input[..n];
        match op % 6 {
            0 | 1 => {
                if let Ok(o) = ctx.update(input, inl, room(kind, inl)) {
                    assert!(o.data.len() <= room(kind, inl).max(inl.div_ceil(8)));
                }
            }
            2 => {
                if let Ok(o) = ctx.finalize(room(kind, 0)) {
                    assert!(o.data.len() <= kind.block_size());
                }
            }
            3 => {
                if let Ok(o) = ctx.cipher(input, inl, room(kind, inl)) {
                    assert!(o.data.len() <= room(kind, inl));
                }
            }
            4 => {
                if let Some(g) = ctx.generic_mut() {
                    let _ = g.set_num(u32::from(op >> 3));
                }
            }
            _ => {
                let _ = ctx.init(op & 0x80 != 0, (op & 0x40 != 0).then_some(key), iv);
            }
        }
        rest = tail.get(len.min(tail.len())..).unwrap_or_default();
    }

    // Encrypt and decrypt the script as data: the same steps give it back.
    let mut enc = Ctx::new(kind);
    enc.init(true, Some(key), iv).unwrap();
    let mut ct = Vec::new();
    for chunk in script.chunks(usize::from(head % 37) + 1) {
        ct.extend_from_slice(
            &enc.update(chunk, chunk.len(), room(kind, chunk.len()))
                .unwrap()
                .data,
        );
    }
    ct.extend_from_slice(&enc.finalize(room(kind, 0)).unwrap().data);
    let mut dec = Ctx::new(kind);
    dec.init(false, Some(key), iv).unwrap();
    let mut pt = Vec::new();
    for chunk in ct.chunks(usize::from(head % 13) + 1) {
        pt.extend_from_slice(
            &dec.update(chunk, chunk.len(), room(kind, chunk.len()))
                .unwrap()
                .data,
        );
    }
    pt.extend_from_slice(&dec.finalize(room(kind, 0)).unwrap().data);
    assert_eq!(pt, script);
});
