//! Fuzzes QUIC transport parameter decoding (RFC 9000, section 18), as a client and as a server
//! read them: what decodes must encode and decode back to the same parameters. Nothing may
//! panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_quic::wire::TransportParams;

fuzz_target!(|data: &[u8]| {
    for from_server in [false, true] {
        if let Ok(tp) = TransportParams::decode(data, from_server) {
            let enc = tp.encode().expect("decoded parameters encode");
            let again = TransportParams::decode(&enc, from_server).expect("and decode");
            assert_eq!(tp, again);
        }
    }
});
