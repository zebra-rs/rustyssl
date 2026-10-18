//! Fuzzes DTLS's record and handshake layers: the input split into datagrams (each a 16-bit
//! length and its octets) and fed to a DTLS client (after its ClientHello) and a DTLS server
//! (before anything), which step until they need input or fail; and the same datagrams read
//! by the record layer alone in plaintext and under TLS 1.2 AES-GCM, so headers, the replay
//! window, held records, fragments, reassembly and reordering all see attacker data. Nothing
//! may panic, and buffering stays bounded.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_tls::conn::{Config, Connection, Event};
use rustyssl_tls::crypto::AeadAlg;
use rustyssl_tls::record::dtls::DRead;
use rustyssl_tls::record::{Mode, Protection, RecordReader};
use rustyssl_tls::testprov::TestProvider;

/// The datagrams of the input.
fn datagrams(mut data: &[u8]) -> Vec<&[u8]> {
    let mut v = Vec::new();
    while let [hi, lo, rest @ ..] = data {
        let n = (usize::from(*hi) << 8 | usize::from(*lo)).min(rest.len());
        let (d, r) = rest.split_at(n);
        v.push(d);
        data = r;
    }
    v
}

/// Steps until the connection waits or fails.
fn run(c: &mut Connection, p: &TestProvider) {
    for _ in 0..200 {
        match c.step(p, true) {
            Ok(Event::NeedInput | Event::Idle | Event::Closed | Event::Interrupted) | Err(_) => {
                return;
            }
            Ok(Event::Request(_)) => return,
            Ok(Event::Output) => {
                let _ = c.take_datagrams();
            }
            Ok(_) => {}
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let p = TestProvider::new(b"dtls-fuzz");
    let dgrams = datagrams(data);
    for server in [false, true] {
        let cfg = Config {
            server,
            dtls: true,
            dtls_mtu: 512,
            max_cert_list: 102_400,
            ciphers: rustyssl_tls::suites::all().collect(),
            ..Config::default()
        };
        let mut c = Connection::new(cfg);
        run(&mut c, &p);
        for d in &dgrams {
            c.feed_datagram(d);
            run(&mut c, &p);
        }
    }
    for prot in 0..2 {
        let mut rr = RecordReader::new_dtls(true);
        if prot == 1 {
            if let Ok(pr) = Protection::aead12(&p, AeadAlg::Aes128Gcm, &[1; 16], &[2; 4], 0) {
                rr.set_protection(Mode::Tls12(0xfefd), pr);
            }
        }
        for d in &dgrams {
            let mut rest: &[u8] = d;
            while !rest.is_empty() {
                match rr.read_dtls(&p, rest) {
                    Ok(DRead::Record { consumed, .. } | DRead::Dropped { consumed, .. }) => {
                        rest = rest.get(consumed.max(1)..).unwrap_or_default();
                    }
                    Err(_) => break,
                }
            }
            while rr.take_replay().is_some() {}
        }
    }
});
