//! Fuzzes a QUIC listener and a client with arbitrary datagrams: the input is a series of
//! (target, time step, length, octets) records delivered to a server port, a client connecting
//! to it, or both, interleaved with their own traffic and timers. Nothing may panic, and every
//! datagram sent fits the 1200-octet limit.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_quic::channel::{MAX_DGRAM, PeerAddr};
use rustyssl_quic::port::{Port, PortConfig};
use rustyssl_quic::testprov::TestProvider;
use rustyssl_quic::time::{Duration, Time};
use rustyssl_quic::tls::{Handshake, TestHandshake};
use rustyssl_tls::crypto::AeadAlg;

fuzz_target!(|data: &[u8]| {
    let p = TestProvider::new(b"quic_port");
    let suite = TestHandshake::suite(AeadAlg::Aes128Gcm).expect("suite");
    let validate = data.first().is_some_and(|b| b & 1 == 1);
    let mut server = Port::new(PortConfig {
        listen: true,
        validate_addr: validate,
        new_handshake: Some(Box::new(move || {
            Box::new(TestHandshake::new(true, suite)) as Box<dyn Handshake>
        })),
        ..PortConfig::default()
    });
    let mut client = Port::new(PortConfig::default());
    let caddr = PeerAddr(b"c".to_vec());
    let saddr = PeerAddr(b"s".to_vec());
    let mut now = Time(1_000_000_000);
    let _ = client.connect(
        &p,
        Box::new(TestHandshake::new(false, suite)),
        saddr.clone(),
        now,
    );
    let mut d = data.get(1..).unwrap_or(&[]);
    while let [target, step, l0, l1, rest @ ..] = d {
        let len = usize::from(u16::from_be_bytes([*l0, *l1]))
            .min(rest.len())
            .min(1500);
        let (dgram, next) = rest.split_at(len);
        d = next;
        now = now.add(Duration::from_millis(u64::from(*step)));
        match target % 3 {
            0 => server.handle_datagram(&p, now, &caddr, dgram),
            1 => client.handle_datagram(&p, now, &saddr, dgram),
            _ => {
                server.handle_datagram(&p, now, &caddr, dgram);
                client.handle_datagram(&p, now, &saddr, dgram);
            }
        }
        // Their own traffic, delivered at once.
        for _ in 0..16 {
            let mut any = false;
            if let Some((_, out)) = client.poll_transmit(&p, now) {
                assert!(out.len() <= MAX_DGRAM);
                server.handle_datagram(&p, now, &caddr, &out);
                any = true;
            }
            if let Some((_, out)) = server.poll_transmit(&p, now) {
                assert!(out.len() <= MAX_DGRAM);
                client.handle_datagram(&p, now, &saddr, &out);
                any = true;
            }
            if !any {
                break;
            }
        }
        client.handle_timeout(&p, now);
        server.handle_timeout(&p, now);
        while server.accept().is_some() {}
    }
});
