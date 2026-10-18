//! A UDP relay between a DTLS client and server that drops, duplicates and reorders the
//! handshake's datagrams by a seeded schedule (`+faults`, `--seed`).
//!
//! Only datagrams whose first record is a handshake message or a ChangeCipherSpec are faulted:
//! DTLS retransmits flights, not application data or alerts, so a lost data record would end
//! the case rather than test recovery. Which datagram gets which fault depends only on the seed,
//! the case, the direction and the datagram's place among the faultable ones, so a schedule
//! reproduces with the same `--seed` (how many retransmissions it takes may still vary with
//! timing).

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::util::Result;

/// The schedule's seed (`--seed`), the same for every case unless set.
static SEED: OnceLock<u64> = OnceLock::new();

/// The default seed.
const DEFAULT_SEED: u64 = 1;

/// How long a held (reordered) datagram waits for the next one before it goes out anyway.
const HOLD: Duration = Duration::from_millis(100);

/// The most faultable datagrams in a row that are dropped, per direction, so that a flight's
/// retransmissions get through within the cases' time limit.
const MAX_DROPS_IN_A_ROW: u32 = 2;

pub(super) fn set_seed(seed: u64) {
    let _ = SEED.set(seed);
}

pub(super) fn seed() -> u64 {
    *SEED.get().unwrap_or(&DEFAULT_SEED)
}

/// What the relay did, per direction (client to server, server to client).
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Counts {
    pub forwarded: u32,
    pub dropped: u32,
    pub duplicated: u32,
    pub reordered: u32,
}

/// A running relay; stopped when dropped.
pub(super) struct Relay {
    pub port: u16,
    stop: Arc<AtomicBool>,
    counts: Arc<Mutex<[Counts; 2]>>,
    thread: Option<JoinHandle<()>>,
}

impl Relay {
    /// Listens on a free local port and relays to the server's port.
    pub(super) fn start(server_port: u16, case: &str) -> Result<Self> {
        let sock = UdpSocket::bind("127.0.0.1:0")?;
        sock.set_read_timeout(Some(Duration::from_millis(10)))?;
        let port = sock.local_addr()?.port();
        let server: SocketAddr = format!("127.0.0.1:{server_port}").parse()?;
        let stop = Arc::new(AtomicBool::new(false));
        let counts = Arc::new(Mutex::new([Counts::default(); 2]));
        let schedules = [
            Schedule::new(seed(), case, 0),
            Schedule::new(seed(), case, 1),
        ];
        let (s, c) = (Arc::clone(&stop), Arc::clone(&counts));
        let thread = std::thread::spawn(move || relay(&sock, server, &s, &c, schedules));
        Ok(Self {
            port,
            stop,
            counts,
            thread: Some(thread),
        })
    }

    /// What it did so far.
    pub(super) fn counts(&self) -> [Counts; 2] {
        *self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// A fault for one datagram.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    Drop,
    Duplicate,
    Reorder,
}

/// One direction's schedule: a SplitMix64 stream from the seed, the case and the direction.
struct Schedule {
    state: u64,
    drops_in_a_row: u32,
}

impl Schedule {
    fn new(seed: u64, case: &str, direction: u64) -> Self {
        // FNV-1a over the case's name, mixed with the seed and the direction.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in case.bytes() {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
        Self {
            state: seed ^ h ^ direction.wrapping_mul(0x9e37_79b9_7f4a_7c15),
            drops_in_a_row: 0,
        }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// The next faultable datagram's fault: about 20% dropped, 10% duplicated, 15% held back.
    fn fault(&mut self) -> Fault {
        let f = match self.next() % 100 {
            0..20 if self.drops_in_a_row < MAX_DROPS_IN_A_ROW => Fault::Drop,
            20..30 => Fault::Duplicate,
            30..45 => Fault::Reorder,
            _ => Fault::None,
        };
        if f == Fault::Drop {
            self.drops_in_a_row += 1;
        } else {
            self.drops_in_a_row = 0;
        }
        f
    }
}

/// Whether a datagram is one the schedule faults: its first record a handshake message (22) or
/// a ChangeCipherSpec (20).
fn faultable(d: &[u8]) -> bool {
    d.len() >= 13 && matches!(d.first(), Some(20 | 22))
}

fn relay(
    sock: &UdpSocket,
    server: SocketAddr,
    stop: &AtomicBool,
    counts: &Mutex<[Counts; 2]>,
    mut schedules: [Schedule; 2],
) {
    let mut client: Option<SocketAddr> = None;
    // A held datagram per direction, and when it was held.
    let mut held: [Option<(Vec<u8>, Instant)>; 2] = [None, None];
    let mut buf = vec![0u8; 65536];
    let send = |dir: usize, d: &[u8], client: Option<SocketAddr>| {
        let to = if dir == 0 { Some(server) } else { client };
        if let Some(to) = to {
            let _ = sock.send_to(d, to);
        }
    };
    while !stop.load(Ordering::Relaxed) {
        // Held datagrams whose wait is over go out.
        for (dir, h) in held.iter_mut().enumerate() {
            if h.as_ref().is_some_and(|(_, at)| at.elapsed() >= HOLD)
                && let Some((d, _)) = h.take()
            {
                send(dir, &d, client);
            }
        }
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            continue;
        };
        let Some(d) = buf.get(..n) else {
            continue;
        };
        let dir = if from == server {
            1
        } else {
            client = Some(from);
            0
        };
        let fault = if faultable(d) {
            schedules.get_mut(dir).map_or(Fault::None, Schedule::fault)
        } else {
            Fault::None
        };
        let mut c = counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(c) = c.get_mut(dir) else {
            continue;
        };
        match fault {
            Fault::Drop => c.dropped += 1,
            Fault::Reorder if held.get(dir).is_some_and(Option::is_none) => {
                // Held until the next datagram this way has gone out (or the wait is over).
                c.reordered += 1;
                if let Some(h) = held.get_mut(dir) {
                    *h = Some((d.to_vec(), Instant::now()));
                }
            }
            _ => {
                send(dir, d, client);
                c.forwarded += 1;
                if fault == Fault::Duplicate {
                    send(dir, d, client);
                    c.duplicated += 1;
                }
                if let Some((h, _)) = held.get_mut(dir).and_then(Option::take) {
                    send(dir, &h, client);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_schedule_reproduces_from_its_seed() {
        let run = |seed, case| {
            let mut s = Schedule::new(seed, case, 0);
            (0..64).map(|_| s.fault() as u8).collect::<Vec<_>>()
        };
        assert_eq!(run(7, "dtls12-default"), run(7, "dtls12-default"));
        assert_ne!(run(7, "dtls12-default"), run(8, "dtls12-default"));
        assert_ne!(run(7, "dtls12-default"), run(7, "dtls12-mtu"));
    }

    #[test]
    fn drops_are_bounded_in_a_row() {
        let mut s = Schedule::new(3, "x", 1);
        let mut row = 0;
        for _ in 0..10_000 {
            if s.fault() == Fault::Drop {
                row += 1;
                assert!(row <= MAX_DROPS_IN_A_ROW);
            } else {
                row = 0;
            }
        }
    }

    #[test]
    fn only_handshake_and_ccs_records_are_faulted() {
        let rec = |t: u8| {
            let mut v = vec![t, 0xfe, 0xfd];
            v.resize(20, 0);
            v
        };
        assert!(faultable(&rec(22)));
        assert!(faultable(&rec(20)));
        assert!(!faultable(&rec(23)));
        assert!(!faultable(&rec(21)));
        assert!(!faultable(&[22, 0xfe]));
    }
}
