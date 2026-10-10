//! Fuzzes the other modes' contexts with arbitrary operations: CTS, XTS (both standards), the
//! key wraps, triple DES's, the AES-CBC-HMAC composites (with TLS AADs and MAC keys), SIV, and
//! GCM-SIV. The first octets pick the context and direction, and the rest is a script of
//! updates (of lengths read from it, over its own octets), finals, `cipher` calls, parameter
//! sets, and re-inits. Nothing may panic and every output must fit its room; then the script,
//! encrypted, must decrypt back.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_crypto::provided::aead::Io;
use rustyssl_crypto::provided::cipher::{Ctx, Kind, Mode};
use rustyssl_crypto::provided::siv::{GcmSiv, Siv};
use rustyssl_crypto::sym::BlockAlgorithm::{self, Aes, Camellia, Sm4, TripleDes};

const fn block(algorithm: BlockAlgorithm, key_len: usize, mode: Mode) -> Kind {
    Kind::Block {
        algorithm,
        key_len,
        mode,
    }
}

const KINDS: [Kind; 11] = [
    block(Aes, 16, Mode::CbcCts),
    block(Camellia, 32, Mode::CbcCts),
    block(Aes, 32, Mode::Xts),
    block(Sm4, 32, Mode::Xts),
    block(Aes, 16, Mode::Wrap),
    block(Aes, 24, Mode::WrapPad),
    block(Aes, 32, Mode::WrapInv),
    block(Aes, 16, Mode::WrapPadInv),
    block(TripleDes, 24, Mode::Wrap),
    block(Aes, 16, Mode::CbcHmacSha1),
    block(Aes, 32, Mode::CbcHmacSha256),
];

fn io(input: Option<&[u8]>, inl: usize, out: bool, room: usize) -> Io<'_> {
    Io {
        input,
        inl,
        out,
        in_place: false,
        outsize: room,
    }
}

/// A script on a generic-context mode.
fn generic(head: u8, script: &[u8]) {
    let kind = KINDS[usize::from(head >> 1) % KINDS.len()];
    let key: Vec<u8> = (0..kind.key_len()).map(|i| i as u8 ^ 0x5a).collect();
    let iv = [0xa5u8; 16];
    let iv = &iv[..kind.iv_len()];
    let mut ctx = Ctx::new(kind);
    let _ = ctx.init(head & 1 != 0, Some(&key), (!iv.is_empty()).then_some(iv));
    let mut rest = script;
    while let Some((&op, tail)) = rest.split_first() {
        let len = usize::from(tail.first().copied().unwrap_or(0));
        let input = &tail[..len.min(tail.len())];
        let inl = input.len();
        let room = inl + 64;
        match op % 9 {
            0 | 1 => {
                let r = if kind.cts() {
                    ctx.update(input, inl, room).ok()
                } else {
                    ctx.process(io(Some(input), inl, op & 0x80 == 0, room), false)
                        .and_then(Result::ok)
                };
                if let Some(o) = r {
                    assert!(o.at + o.data.len() <= room);
                }
            }
            2 => {
                if let Some(Ok(o)) = ctx.process(io(Some(input), inl, true, room), true) {
                    assert!(o.at + o.data.len() <= room);
                }
            }
            3 => {
                let _ = ctx.process_final().unwrap_or_else(|| ctx.finalize(16));
            }
            4 => {
                if let Some(g) = ctx.generic_mut() {
                    g.set_cts_mode(op >> 6);
                    g.set_xts_ieee(op & 0x20 != 0);
                }
            }
            5 => {
                if let Some(g) = ctx.generic_mut() {
                    let _ = g.set_mac_key(input);
                }
            }
            6 => {
                if let Some(g) = ctx.generic_mut() {
                    let mut aad = [0u8; 13];
                    for (a, b) in aad.iter_mut().zip(input) {
                        *a = *b;
                    }
                    let _ = g.set_composite_tls_aad(&mut aad);
                    let _ = g.set_multiblock_aad(input, u32::from(op >> 4), op & 8 != 0);
                    let _ = g.set_max_send_fragment(inl);
                    let _ = g.multiblock_max_bufsize();
                }
            }
            7 => {
                let _ = ctx.init(op & 0x80 != 0, (op & 0x40 != 0).then_some(&key[..]), None);
            }
            _ => {
                let _ = ctx.init(op & 0x80 != 0, None, (op & 0x40 != 0).then_some(iv));
            }
        }
        rest = tail.get(len.min(tail.len())..).unwrap_or_default();
    }

    // CTS, XTS, and the AES key wraps take the script whole and give it back.
    let n = script.len();
    let fits = match kind {
        k if k.cts() || k.xts() => n >= 16,
        k if k.wrap() && kind.iv_len() == 8 => n >= 16 && n % 8 == 0,
        k if k.wrap() && kind.iv_len() == 4 => n >= 1,
        _ => false,
    };
    if !fits || n > 4096 {
        return;
    }
    let pass = |enc: bool, input: &[u8]| -> Vec<u8> {
        let mut c = Ctx::new(kind);
        c.init(enc, Some(&key), (!iv.is_empty()).then_some(iv)).unwrap();
        let o = if kind.cts() {
            c.update(input, input.len(), input.len() + 16).unwrap()
        } else {
            c.process(io(Some(input), input.len(), true, input.len() + 16), false)
                .unwrap()
                .unwrap()
        };
        assert!(o.failed.is_none() && o.raised.is_none());
        o.data.to_vec()
    };
    let ct = pass(true, script);
    assert_eq!(pass(false, &ct), script);
}

/// SIV or GCM-SIV: arbitrary steps, then the script as a message and back.
fn sivs(head: u8, script: &[u8]) {
    let gcm = head & 2 != 0;
    let keylen = if gcm { 16 } else { 32 };
    let key: Vec<u8> = (0..keylen).map(|i| i as u8 ^ 0x3c).collect();
    let nonce = [7u8; 12];
    let mut siv = Siv::new(keylen);
    let mut gs = GcmSiv::new(keylen);
    let enc = head & 1 != 0;
    let _ = siv.init(enc, Some(&key));
    let _ = gs.init(enc, Some(&key), Some(&nonce));
    let mut rest = script;
    while let Some((&op, tail)) = rest.split_first() {
        let len = usize::from(tail.first().copied().unwrap_or(0));
        let input = &tail[..len.min(tail.len())];
        let inl = input.len();
        match op % 6 {
            0 | 1 => {
                let out = op & 0x80 == 0;
                let r = if gcm {
                    gs.cipher(Some(input), inl, out, inl)
                } else {
                    siv.cipher(Some(input), inl, out, inl)
                };
                if let Ok(o) = r {
                    assert!(o.data.len() <= inl);
                }
            }
            2 => {
                let _ = if gcm { gs.finalize() } else { siv.finalize() };
            }
            3 => {
                if gcm {
                    let _ = gs.set_tag(input);
                    let _ = gs.tag(inl);
                    gs.set_speed(u32::from(op >> 7));
                } else {
                    let _ = siv.set_tag(input);
                    let _ = siv.tag(inl);
                    siv.set_speed(u32::from(op >> 6));
                    siv.reset_final();
                }
            }
            _ => {
                let k = (op & 0x40 != 0).then_some(&key[..]);
                let _ = siv.init(op & 0x80 != 0, k);
                let _ = gs.init(op & 0x80 != 0, k, (op & 0x20 != 0).then_some(&nonce[..]));
            }
        }
        rest = tail.get(len.min(tail.len())..).unwrap_or_default();
    }

    let aad = &script[..script.len().min(usize::from(head >> 3))];
    let msg = &script[aad.len()..];
    if gcm {
        let mut e = GcmSiv::new(keylen);
        e.init(true, Some(&key), Some(&nonce)).unwrap();
        e.cipher(Some(aad), aad.len(), false, aad.len()).unwrap();
        let ct = e.cipher(Some(msg), msg.len(), true, msg.len()).unwrap().data.to_vec();
        e.finalize().unwrap();
        let tag = e.tag(16).unwrap();
        let mut d = GcmSiv::new(keylen);
        d.init(false, Some(&key), Some(&nonce)).unwrap();
        d.set_tag(&tag).unwrap();
        d.cipher(Some(aad), aad.len(), false, aad.len()).unwrap();
        let pt = d.cipher(Some(&ct), ct.len(), true, ct.len()).unwrap().data.to_vec();
        assert_eq!(pt, msg);
        d.finalize().unwrap();
    } else {
        let mut e = Siv::new(keylen);
        e.init(true, Some(&key)).unwrap();
        e.cipher(Some(aad), aad.len(), false, aad.len()).unwrap();
        let ct = e.cipher(Some(msg), msg.len(), true, msg.len()).unwrap().data.to_vec();
        let tag = e.tag(16).unwrap();
        let mut d = Siv::new(keylen);
        d.init(false, Some(&key)).unwrap();
        d.set_tag(&tag).unwrap();
        d.cipher(Some(aad), aad.len(), false, aad.len()).unwrap();
        let o = d.cipher(Some(&ct), ct.len(), true, ct.len()).unwrap();
        assert!(o.failed.is_none());
        assert_eq!(o.data.to_vec(), msg);
        d.finalize().unwrap();
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&head, script)) = data.split_first() else {
        return;
    };
    if head & 0x80 != 0 {
        sivs(head, script);
    } else {
        generic(head, script);
    }
});
