#![allow(clippy::arithmetic_side_effects, reason = "test code")]
#![allow(clippy::indexing_slicing, reason = "test code")]
#![allow(clippy::cast_possible_truncation, reason = "test code")]

use super::*;
use crate::testutil::Rng;

fn code(c: core::ffi::c_int) -> u64 {
    crate::error::code(c)
}

#[test]
fn range_set() {
    let mut r = RangeSet::default();
    r.insert(10, 20);
    r.insert(30, 40);
    r.insert(20, 30);
    assert_eq!(r.0, [(10, 40)]);
    r.remove(15, 25);
    assert_eq!(r.0, [(10, 15), (25, 40)]);
    assert!(r.covers(26, 40));
    assert!(!r.covers(14, 16));
    r.insert(0, 100);
    assert_eq!(r.0, [(0, 100)]);
}

#[test]
fn recv_buf_reassembles_overlaps() {
    let data: Vec<u8> = (0..100u8).collect();
    let mut b = RecvBuf::default();
    b.insert(50, &data[50..80], 0).unwrap();
    b.insert(10, &data[10..60], 0).unwrap();
    assert_eq!(b.available(), 0);
    b.insert(0, &data[0..20], 0).unwrap();
    b.set_final_size(100);
    b.insert(70, &data[70..100], 0).unwrap();
    assert!(b.all_received());
    let mut out = [0u8; 64];
    assert_eq!(b.read(&mut out), (64, false));
    assert_eq!(out[..], data[..64]);
    // Old data again is ignored.
    b.insert(0, &data[0..90], 0).unwrap();
    let mut out2 = [0u8; 64];
    assert_eq!(b.read(&mut out2), (36, true));
    assert_eq!(out2[..36], data[64..]);
}

#[test]
fn recv_buf_bounds_fragments() {
    let mut b = RecvBuf::default();
    let mut err = None;
    for i in 0..(MAX_RECV_FRAGMENTS as u64 + 1) {
        if let Err(e) = b.insert(i * 2 + 1, &[0], 0) {
            err = Some(e);
        }
    }
    assert!(err.is_some());
}

/// A sender and receiver over a channel that loses, reorders and duplicates chunks: the
/// receiver gets exactly what was written.
#[test]
fn send_recv_property() {
    for seed in 1..60u64 {
        let mut rng = Rng(seed);
        let len = rng.below(20_000) as usize;
        let msg = rng.bytes(len);
        let mut tx = SendBuf::new(4096);
        let mut rx = RecvBuf::default();
        let mut written = 0;
        let mut got = Vec::new();
        let mut in_flight: Vec<Chunk> = Vec::new();
        for _round in 0..100_000 {
            if written < msg.len() {
                written += tx.write(&msg[written..]);
            }
            if written == msg.len() && !tx.is_finished() {
                tx.finish();
            }
            let max = 1 + rng.below(1500) as usize;
            if let Some(c) = tx.next_chunk(max, u64::MAX) {
                in_flight.push(c);
            }
            if in_flight.is_empty() || rng.chance(30) {
                continue;
            }
            let i = rng.below(in_flight.len() as u64) as usize;
            let c = in_flight.swap_remove(i);
            let len = c.data.len() as u64;
            if rng.chance(15) {
                tx.on_lost(c.offset, len, c.fin);
                continue;
            }
            if rng.chance(10) {
                in_flight.push(c.clone());
            }
            rx.insert(c.offset, &c.data, 0).unwrap();
            if c.fin {
                rx.set_final_size(c.offset + len);
            }
            tx.on_acked(c.offset, len, c.fin);
            let mut buf = [0u8; 700];
            loop {
                let (n, _) = rx.read(&mut buf);
                got.extend_from_slice(&buf[..n]);
                if n == 0 {
                    break;
                }
            }
            if tx.is_totally_acked() {
                break;
            }
        }
        assert!(tx.is_totally_acked(), "seed {seed}");
        assert_eq!(got, msg, "seed {seed}");
        let (_, fin) = rx.read(&mut [0u8; 1]);
        assert!(fin);
    }
}

fn pair() -> (StreamMap, StreamMap) {
    let mut c = StreamMap::new(false);
    let mut s = StreamMap::new(true);
    let lim = StreamLimits {
        peer_bidi_local: DEFAULT_INIT_STREAM_RXFC_WND,
        peer_bidi_remote: DEFAULT_INIT_STREAM_RXFC_WND,
        peer_uni: DEFAULT_INIT_STREAM_RXFC_WND,
    };
    c.set_peer_params(DEFAULT_INIT_CONN_RXFC_WND, lim, 100, 100);
    s.set_peer_params(DEFAULT_INIT_CONN_RXFC_WND, lim, 100, 100);
    (c, s)
}

#[test]
fn stream_lifecycle() {
    let (mut c, mut s) = pair();
    let id = c.open(true).unwrap();
    assert_eq!(id, 0);
    assert_eq!(c.open(false), Some(2));
    assert_eq!(c.send(id, b"hello", true).unwrap(), 5);
    assert_eq!(c.active(), [0]);
    let ch = c.next_chunk(id, 1000).unwrap();
    assert_eq!((ch.offset, &ch.data[..], ch.fin), (0, &b"hello"[..], true));
    s.on_stream(0x0b, id, ch.offset, &ch.data, ch.fin).unwrap();
    assert_eq!(s.poll_event(), Some(StreamEvent::Incoming(0)));
    assert_eq!(s.poll_event(), Some(StreamEvent::Readable(0)));
    assert_eq!(s.accept(Time(0)), Some(0));
    let mut buf = [0u8; 16];
    assert_eq!(
        s.recv(0, &mut buf, Time(0), Duration::ZERO).unwrap(),
        (5, true)
    );
    c.on_stream_acked(id, 0, 5, true);
    assert_eq!(
        c.get(id).unwrap().send.as_ref().unwrap().state,
        SendState::DataRecvd
    );
    // The server answers and finishes; both release; both forget the stream.
    s.send(0, b"bye", true).unwrap();
    let ch = s.next_chunk(0, 1000).unwrap();
    c.on_stream(0x0f, 0, ch.offset, &ch.data, ch.fin).unwrap();
    s.on_stream_acked(0, 0, 3, true);
    assert_eq!(
        c.recv(0, &mut buf, Time(0), Duration::ZERO).unwrap(),
        (3, true)
    );
    c.release(0);
    s.release(0);
    assert!(c.get(0).is_none());
    assert!(s.get(0).is_none());
    // Data for the deleted stream is ignored; a local stream never opened is an error.
    s.on_stream(0x08, 0, 0, b"x", false).unwrap();
    let e = c.on_stream(0x08, 1 << 2, 0, b"x", false).unwrap_err();
    assert_eq!(e.code, code(rustyssl_abi::OSSL_QUIC_ERR_STREAM_STATE_ERROR));
}

#[test]
fn stream_errors_follow_openssl() {
    let (mut c, mut s) = pair();
    // STREAM on a client's unidirectional stream at the client: TX only.
    let uni = c.open(false).unwrap();
    let e = c.on_stream(0x08, uni, 0, b"x", false).unwrap_err();
    assert_eq!(e.code, code(rustyssl_abi::OSSL_QUIC_ERR_STREAM_STATE_ERROR));
    // RESET_STREAM for a TX-only stream.
    let e = c.on_reset_stream(uni, 0, 0).unwrap_err();
    assert_eq!(e.reason, "RESET_STREAM frame for TX only stream");
    // Too many streams.
    let e = s.on_stream(0x08, 100 << 2, 0, b"x", false).unwrap_err();
    assert_eq!(e.code, code(rustyssl_abi::OSSL_QUIC_ERR_STREAM_LIMIT_ERROR));
    // Implicit creation of lower streams (on a new connection: errors are fatal).
    let (_, mut s) = pair();
    s.on_stream(0x08, 3 << 2, 0, b"x", false).unwrap();
    assert_eq!(s.accept_queue_len(), 4);
    // Flow control.
    let e = s
        .on_stream(0x0c, 4, DEFAULT_INIT_STREAM_RXFC_WND, b"x", false)
        .unwrap_err();
    assert_eq!(e.code, code(rustyssl_abi::OSSL_QUIC_ERR_FLOW_CONTROL_ERROR));
    // Final size changes.
    let (_, mut s) = pair();
    s.on_stream(0x09, 0, 0, b"abc", true).unwrap();
    let e = s.on_stream(0x0c, 0, 3, b"d", false).unwrap_err();
    assert_eq!(e.code, code(rustyssl_abi::OSSL_QUIC_ERR_FINAL_SIZE_ERROR));
    assert!(s.on_max_streams(true, MAX_STREAM_COUNT + 1).is_err());
}

#[test]
fn stop_sending_resets_and_limits_open() {
    let (mut c, mut s) = pair();
    let id = c.open(true).unwrap();
    c.send(id, b"data", false).unwrap();
    let ch = c.next_chunk(id, 1000).unwrap();
    s.on_stream(0x08, id, 0, &ch.data, false).unwrap();
    s.stop_sending(id, 7).unwrap();
    assert_eq!(s.take_stop_sending(id), Some(7));
    c.on_stop_sending(id, 7).unwrap();
    assert_eq!(c.take_reset(id), Some((7, 4)));
    s.on_reset_stream(id, 7, 4).unwrap();
    assert_eq!(s.reset_code(id), Some(7));
    assert!(s.recv(id, &mut [0; 4], Time(0), Duration::ZERO).is_err());
    // The peer's stream limit.
    let mut c = StreamMap::new(false);
    let zero = StreamLimits {
        peer_bidi_local: 0,
        peer_bidi_remote: 0,
        peer_uni: 0,
    };
    c.set_peer_params(0, zero, 1, 0);
    assert!(c.open(true).is_some());
    assert!(c.open(true).is_none());
    assert_eq!(c.take_streams_blocked(true), Some(1));
    assert!(c.open(false).is_none());
    c.on_max_streams(true, 2).unwrap();
    let id = c.open(true).unwrap();
    // No credit: nothing to send.
    c.send(id, b"x", false).unwrap();
    assert!(c.next_chunk(id, 100).is_none());
}

#[test]
fn accept_retires_stream_credit() {
    let (_, mut s) = pair();
    for i in 0..30u64 {
        s.on_stream(0x08, i << 2, 0, b"x", false).unwrap();
        s.accept(Time(0)).unwrap();
    }
    // 25 accepted leaves 75 = 3/4 of the window: a new MAX_STREAMS.
    assert_eq!(s.take_max_streams(true), Some(125));
    assert_eq!(s.take_max_streams(true), None);
}
