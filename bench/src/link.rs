//! A simulated network path in userspace: one-way delay, jitter and (for UDP)
//! loss, with packet counters. Used when the kernel's `netem` isn't available.

use std::collections::BinaryHeap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Path characteristics, applied in each direction.
#[derive(Debug, Clone, Copy)]
pub struct Impairment {
    /// One-way delay (RTT / 2).
    pub delay: Duration,
    /// Extra delay, uniform in `[0, jitter]`, per packet (UDP) or chunk (TCP).
    pub jitter: Duration,
    /// Fraction of UDP datagrams dropped, `0.0..1.0`. Not applicable to TCP.
    pub loss: f64,
}

/// Packet and byte counters, per direction.
#[derive(Default)]
pub struct Counters {
    pub up_packets: AtomicU64,
    pub up_bytes: AtomicU64,
    pub down_packets: AtomicU64,
    pub down_bytes: AtomicU64,
}

impl Counters {
    pub fn snapshot(&self) -> [u64; 4] {
        [
            self.up_packets.load(Ordering::Relaxed),
            self.up_bytes.load(Ordering::Relaxed),
            self.down_packets.load(Ordering::Relaxed),
            self.down_bytes.load(Ordering::Relaxed),
        ]
    }
}

/// A small, fast PRNG (xorshift64*), seeded from the OS, for jitter and loss.
pub struct Rng(u64);

impl Rng {
    pub fn new() -> Self {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).expect("OS random number generator");
        Rng(u64::from_le_bytes(b) | 1)
    }

    pub fn next_f64(&mut self) -> f64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        (self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 11) as f64 / (1u64 << 53) as f64
    }

    pub fn jitter(&mut self, max: Duration) -> Duration {
        max.mul_f64(self.next_f64())
    }
}

/// Datagrams waiting for their delivery time.
struct Pending {
    due: Instant,
    seq: u64,
    data: Vec<u8>,
    to: SocketAddr,
    via_front: bool,
}

impl PartialEq for Pending {
    fn eq(&self, o: &Self) -> bool {
        (self.due, self.seq) == (o.due, o.seq)
    }
}
impl Eq for Pending {}
impl PartialOrd for Pending {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Pending {
    // Min-heap on (due, seq).
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (o.due, o.seq).cmp(&(self.due, self.seq))
    }
}

/// UDP path: clients send to `front` (a local port); datagrams reach
/// `target` after the impairment, and replies come back the same way.
pub struct UdpLink {
    pub front: SocketAddr,
    pub counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
}

impl UdpLink {
    pub fn start(target: SocketAddr, imp: Impairment) -> std::io::Result<Self> {
        let front = UdpSocket::bind("127.0.0.1:0")?;
        let back = UdpSocket::bind("127.0.0.1:0")?;
        front.set_read_timeout(Some(Duration::from_millis(5)))?;
        back.set_read_timeout(Some(Duration::from_millis(5)))?;
        let front_addr = front.local_addr()?;
        let counters = Arc::new(Counters::default());
        let stop = Arc::new(AtomicBool::new(false));
        let queue = Arc::new((Mutex::new(BinaryHeap::<Pending>::new()), Condvar::new()));
        let client = Arc::new(Mutex::new(None::<SocketAddr>));
        let seq = Arc::new(AtomicU64::new(0));

        // Receivers: one per socket, enqueue with a delivery time.
        for (sock, via_front) in [(front.try_clone()?, true), (back.try_clone()?, false)] {
            let (queue, counters, stop, client, seq) = (
                queue.clone(),
                counters.clone(),
                stop.clone(),
                client.clone(),
                seq.clone(),
            );
            thread::spawn(move || {
                let mut rng = Rng::new();
                let mut buf = vec![0u8; 65536];
                while !stop.load(Ordering::Relaxed) {
                    let Ok((n, from)) = sock.recv_from(&mut buf) else {
                        continue;
                    };
                    // Datagrams arriving at the front come from the client and
                    // go out of the back socket to the target, and vice versa.
                    let (to, out_front) = if via_front {
                        *client.lock().unwrap() = Some(from);
                        counters.up_packets.fetch_add(1, Ordering::Relaxed);
                        counters.up_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        (target, false)
                    } else {
                        counters.down_packets.fetch_add(1, Ordering::Relaxed);
                        counters.down_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        match *client.lock().unwrap() {
                            Some(c) => (c, true),
                            None => continue,
                        }
                    };
                    if rng.next_f64() < imp.loss {
                        continue;
                    }
                    let due = Instant::now() + imp.delay + rng.jitter(imp.jitter);
                    let (lock, cv) = &*queue;
                    lock.lock().unwrap().push(Pending {
                        due,
                        seq: seq.fetch_add(1, Ordering::Relaxed),
                        data: buf[..n].to_vec(),
                        to,
                        via_front: out_front,
                    });
                    cv.notify_one();
                }
            });
        }

        // Sender: deliver each datagram at its due time.
        {
            let (queue, stop) = (queue.clone(), stop.clone());
            thread::spawn(move || {
                let (lock, cv) = &*queue;
                let mut q = lock.lock().unwrap();
                while !stop.load(Ordering::Relaxed) {
                    let now = Instant::now();
                    match q.peek().map(|p| p.due) {
                        Some(due) if due <= now => {
                            let p = q.pop().unwrap();
                            let sock = if p.via_front { &front } else { &back };
                            let _ = sock.send_to(&p.data, p.to);
                        }
                        Some(due) => {
                            q = cv.wait_timeout(q, due - now).unwrap().0;
                        }
                        None => {
                            q = cv.wait_timeout(q, Duration::from_millis(20)).unwrap().0;
                        }
                    }
                }
            });
        }
        Ok(UdpLink {
            front: front_addr,
            counters,
            stop,
        })
    }
}

impl Drop for UdpLink {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// TCP path: delay (and jitter, without reordering) for each chunk in each
/// direction. TCP's own reliability means loss can't be simulated here; use
/// `netem` for that.
pub struct TcpLink {
    pub front: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl TcpLink {
    pub fn start(target: SocketAddr, imp: Impairment) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let front = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        listener.set_nonblocking(true)?;
        {
            let stop = stop.clone();
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((client, _)) => {
                            client.set_nonblocking(false).ok();
                            let Ok(server) = TcpStream::connect(target) else {
                                continue;
                            };
                            for (from, to) in [
                                (client.try_clone().unwrap(), server.try_clone().unwrap()),
                                (server, client),
                            ] {
                                delayed_pipe(from, to, imp);
                            }
                        }
                        Err(_) => thread::sleep(Duration::from_millis(5)),
                    }
                }
            });
        }
        Ok(TcpLink { front, stop })
    }
}

impl Drop for TcpLink {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Copy `from` → `to`, holding each chunk until `delay (+ jitter)` after it
/// was read, in order.
fn delayed_pipe(mut from: TcpStream, mut to: TcpStream, imp: Impairment) {
    let queue = Arc::new((
        Mutex::new(std::collections::VecDeque::<(Instant, Vec<u8>)>::new()),
        Condvar::new(),
    ));
    let done = Arc::new(AtomicBool::new(false));
    {
        let (queue, done) = (queue.clone(), done.clone());
        thread::spawn(move || {
            let mut rng = Rng::new();
            let mut buf = vec![0u8; 64 * 1024];
            let mut last_due = Instant::now();
            loop {
                let n = match from.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                // Never schedule before the previous chunk: TCP is in order.
                let due = (Instant::now() + imp.delay + rng.jitter(imp.jitter)).max(last_due);
                last_due = due;
                let (lock, cv) = &*queue;
                lock.lock().unwrap().push_back((due, buf[..n].to_vec()));
                cv.notify_one();
            }
            done.store(true, Ordering::Relaxed);
            queue.1.notify_one();
        });
    }
    thread::spawn(move || {
        let (lock, cv) = &*queue;
        let mut q = lock.lock().unwrap();
        loop {
            match q.front().map(|(due, _)| *due) {
                Some(due) if due <= Instant::now() => {
                    let (_, data) = q.pop_front().unwrap();
                    drop(q);
                    if to.write_all(&data).is_err() {
                        return;
                    }
                    q = lock.lock().unwrap();
                }
                Some(due) => {
                    let wait = due.saturating_duration_since(Instant::now());
                    q = cv.wait_timeout(q, wait).unwrap().0;
                }
                None if done.load(Ordering::Relaxed) => {
                    let _ = to.shutdown(std::net::Shutdown::Write);
                    return;
                }
                None => {
                    q = cv.wait_timeout(q, Duration::from_millis(20)).unwrap().0;
                }
            }
        }
    });
}
