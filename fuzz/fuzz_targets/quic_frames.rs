//! Fuzzes QUIC frame decoding (RFC 9000, section 19): frames are decoded until the input ends or
//! one is refused; each decoded frame must encode and decode back to itself. Nothing may panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_quic::wire::{Frame, decode_frame, encode_frame};
use rustyssl_tls::codec::Reader;

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let mut n = 0usize;
    while !r.is_empty() {
        let Ok(f) = decode_frame(&mut r) else {
            break;
        };
        let mut out = Vec::new();
        encode_frame(&mut out, &f).expect("a decoded frame encodes");
        let mut r2 = Reader::new(&out);
        let g: Frame<'_> = decode_frame(&mut r2).expect("an encoded frame decodes");
        assert_eq!(f, g);
        assert!(r2.is_empty());
        n += 1;
        assert!(n <= data.len());
    }
});
