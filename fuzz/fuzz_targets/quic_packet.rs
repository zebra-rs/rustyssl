//! Fuzzes QUIC packet parsing and protection (RFC 9000, section 17; RFC 9001, section 5): the
//! input is split into coalesced packets, each unprotected under Initial keys derived from its
//! own DCID, and a payload taken from the input is protected and must open again. Nothing may
//! panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_quic::packet::{self, Outgoing, PacketType};
use rustyssl_quic::testprov::TestProvider;
use rustyssl_quic::wire::ConnId;

fuzz_target!(|data: &[u8]| {
    let Some((&ctl, rest)) = data.split_first() else {
        return;
    };
    let p = TestProvider::new(b"quic_packet");
    let short_len = usize::from(ctl % 21);
    let mut d = rest;
    let mut count = 0;
    while !d.is_empty() {
        let Ok((pkt, next)) = packet::locate(d, short_len) else {
            break;
        };
        assert!(pkt.bytes.len() <= d.len());
        if let Ok((mut c, mut s)) = packet::initial_keys(&p, pkt.dcid.as_bytes()) {
            let _ = packet::unprotect(&mut c, pkt.bytes, pkt.pn_offset, None);
            let _ = packet::unprotect(&mut s, pkt.bytes, pkt.pn_offset, Some(u64::from(ctl)));
        }
        if pkt.ty == PacketType::Retry {
            let _ = packet::retry_tag_valid(&p, &pkt.dcid, pkt.bytes);
        }
        assert!(next.len() < d.len() || next.is_empty());
        d = next;
        count += 1;
        assert!(count <= rest.len());
    }
    // Round trip: protect the input as a payload, locate and open it.
    let dcid = ConnId::new(&rest[..rest.len().min(8)]).unwrap_or_default();
    let Ok((mut tx, _)) = packet::initial_keys(&p, dcid.as_bytes()) else {
        return;
    };
    let Ok((mut rx, _)) = packet::initial_keys(&p, dcid.as_bytes()) else {
        return;
    };
    let pn = u64::from(ctl) * 977;
    let pn_len = packet::pn_len(pn, None);
    let ty = if ctl & 1 == 0 {
        PacketType::Initial
    } else {
        PacketType::Handshake
    };
    let mut payload = rest.to_vec();
    payload.resize(payload.len().max(4), 0);
    let scid = ConnId::default();
    let o = Outgoing {
        ty,
        dcid: &dcid,
        scid: &scid,
        token: &[],
        pn,
        pn_len,
        key_phase: false,
    };
    let mut out = Vec::new();
    if packet::protect(&mut tx, &o, &payload, &mut out).is_ok() {
        let (l, _) = packet::locate(&out, dcid.len()).expect("our packet locates");
        let opened = packet::unprotect(&mut rx, l.bytes, l.pn_offset, None)
            .expect("no protocol error")
            .expect("our packet opens");
        assert_eq!(opened.pn, pn);
        assert_eq!(opened.payload, payload);
    }
});
