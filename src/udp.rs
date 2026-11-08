//! Batched UDP I/O for the QUIC drivers, through `quinn-udp` (safe API):
//!
//! - **send**: a [`Batch`] of equal-size datagrams goes out in one system call
//!   with GSO (Linux) or as one datagram per call elsewhere; batches the
//!   socket can't take right now (`EAGAIN`) wait in a queue, so a full send
//!   buffer delays packets instead of dropping them;
//! - **receive**: `recvmmsg` fills several buffers per call, and with GRO a
//!   buffer holds several datagrams (split at `stride`);
//! - **ECN** marks are carried both ways, so QUIC's congestion control can
//!   react to them.

use std::collections::VecDeque;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::{AsFd, BorrowedFd};

use quinn_proto::EcnCodepoint;
use quinn_udp::{RecvMeta, Transmit, UdpSocketState};

use crate::quic::Batch;

/// Socket buffer sizes to ask for (the kernel may cap them): room for a
/// window's worth of packets at high rates.
const SOCKET_BUFFER: usize = 4 * 1024 * 1024;
/// Size of each receive buffer (a GRO buffer holds up to 64 KiB).
const RECV_BUF: usize = 64 * 1024;
/// Most batches waiting for the socket; beyond that new ones are dropped
/// (QUIC recovers them like any loss).
const MAX_QUEUED: usize = 1024;
/// Most datagrams per GSO batch: a batch is one UDP send of at most 64 KiB,
/// and QUIC datagrams grow up to 1452 bytes with path MTU discovery
/// (32 × 1452 = 46 KiB).
const MAX_SEGMENTS: usize = 32;

/// One received datagram.
pub struct Received<'a> {
    pub from: SocketAddr,
    pub local_ip: Option<IpAddr>,
    pub ecn: Option<EcnCodepoint>,
    pub data: &'a [u8],
}

pub struct UdpIo {
    socket: UdpSocket,
    state: UdpSocketState,
    bufs: Vec<Vec<u8>>,
    meta: Vec<RecvMeta>,
    queue: VecDeque<Batch>,
}

impl UdpIo {
    /// Wrap a socket (made non-blocking).
    pub fn new(socket: UdpSocket) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        let state = UdpSocketState::new((&socket).into())?;
        let _ = state.set_send_buffer_size((&socket).into(), SOCKET_BUFFER);
        let _ = state.set_recv_buffer_size((&socket).into(), SOCKET_BUFFER);
        let n = quinn_udp::BATCH_SIZE.max(1);
        Ok(UdpIo {
            socket,
            state,
            bufs: vec![vec![0u8; RECV_BUF]; n],
            meta: vec![RecvMeta::default(); n],
            queue: VecDeque::new(),
        })
    }

    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Datagrams per send call the socket supports (1 without GSO).
    pub fn max_segments(&self) -> usize {
        self.state.max_gso_segments().clamp(1, MAX_SEGMENTS)
    }

    /// Queue `batches` and send as many as the socket takes now.
    pub fn send(&mut self, batches: impl IntoIterator<Item = Batch>) {
        for b in batches {
            if self.queue.len() < MAX_QUEUED {
                self.queue.push_back(b);
            }
        }
        self.flush();
    }

    /// Send queued batches until the socket would block. Errors other than
    /// "would block" drop the batch: a network outage (no route, network
    /// down while roaming) must never end the session, and QUIC retransmits.
    pub fn flush(&mut self) {
        while let Some(b) = self.queue.front() {
            let t = Transmit {
                destination: b.dest,
                ecn: b
                    .ecn
                    .and_then(|e| quinn_udp::EcnCodepoint::from_bits(e as u8)),
                contents: &b.data,
                segment_size: b.segment_size,
                src_ip: None,
            };
            match self.state.try_send((&self.socket).into(), &t) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                // The kernel refused the batch as a whole (GSO unsupported on
                // this path, or too large): send its datagrams one by one.
                Err(_) if b.segment_size.is_some() => {
                    let b = self.queue.pop_front().expect("front exists");
                    let singles: Vec<Batch> = b
                        .datagrams()
                        .map(|d| Batch {
                            dest: b.dest,
                            data: d.to_vec(),
                            segment_size: None,
                            ecn: b.ecn,
                        })
                        .collect();
                    for s in singles.into_iter().rev() {
                        self.queue.push_front(s);
                    }
                }
                _ => {
                    self.queue.pop_front();
                }
            }
        }
    }

    /// Whether batches are waiting for the socket (poll for writability).
    pub fn wants_write(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Receive what is ready, calling `f` once per datagram. Returns how many
    /// datagrams arrived (0: nothing ready, or a transient error).
    pub fn recv(&mut self, mut f: impl FnMut(Received<'_>)) -> usize {
        let mut slices: Vec<IoSliceMut<'_>> =
            self.bufs.iter_mut().map(|b| IoSliceMut::new(b)).collect();
        let n = match self
            .state
            .recv((&self.socket).into(), &mut slices, &mut self.meta)
        {
            Ok(n) => n,
            // Would block, or a transient error (an ICMP error from a gone
            // peer, a network change): nothing to read now.
            Err(_) => return 0,
        };
        let mut count = 0;
        for (meta, buf) in self.meta.iter().zip(slices.iter()).take(n) {
            let stride = if meta.stride == 0 {
                meta.len
            } else {
                meta.stride
            };
            for d in buf[..meta.len].chunks(stride.max(1)) {
                count += 1;
                f(Received {
                    from: meta.addr,
                    local_ip: meta.dst_ip,
                    ecn: meta.ecn.and_then(|e| EcnCodepoint::from_bits(e as u8)),
                    data: d,
                });
            }
        }
        count
    }
}
