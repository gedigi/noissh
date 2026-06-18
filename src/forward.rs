//! Socket plumbing for forwarding: pairs a non-blocking byte stream (TCP for
//! port forwarding, Unix for agent forwarding) with a reliable session stream,
//! buffering each direction so neither side blocks and handling half-close
//! without dropping buffered data.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsFd, BorrowedFd, RawFd};
use std::os::unix::net::UnixStream;

/// One forwarded connection over a byte stream `S`. The session-stream side is
/// driven by the caller (read/write via the mux); this type owns the local
/// socket plus an outbound buffer for bytes arriving from the session.
///
/// `S` is [`TcpStream`] for `-L`/`-R` port forwarding and [`UnixStream`] for
/// agent forwarding; both implement [`Read`] + [`Write`] + [`AsFd`].
pub struct ForwardConn<S = TcpStream> {
    stream: S,
    /// Bytes received from the session, waiting to be written to the socket.
    out: Vec<u8>,
    /// Socket read side hit EOF (the local peer won't send more).
    read_closed: bool,
    /// The session peer closed its half (we won't receive more session data).
    peer_closed: bool,
    /// We've already sent our FIN (stream close) to the session peer.
    fin_sent: bool,
    /// The socket errored and is unusable.
    dead: bool,
    /// Consecutive flush attempts that made no progress (peer not draining).
    flush_stall: u32,
}

/// Reap a connection whose peer makes no write progress for this many flush
/// attempts (a permanently-stuck local app). At the driver cadence this is on
/// the order of a minute, after which the connection is considered dead.
const FLUSH_STALL_LIMIT: u32 = 3000;

impl ForwardConn<TcpStream> {
    pub fn new(stream: TcpStream) -> std::io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self::from_stream(stream))
    }

    /// Connect out to `target` ("host:port"), returning a non-blocking conn.
    pub fn connect(target: &str) -> std::io::Result<Self> {
        ForwardConn::new(TcpStream::connect(target)?)
    }
}

impl ForwardConn<UnixStream> {
    pub fn new_unix(stream: UnixStream) -> std::io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self::from_stream(stream))
    }

    /// Connect out to a Unix-domain socket `path` (e.g. an SSH agent socket).
    pub fn connect_unix(path: &str) -> std::io::Result<Self> {
        ForwardConn::new_unix(UnixStream::connect(path)?)
    }
}

impl<S: Read + Write + AsFd> ForwardConn<S> {
    /// Wrap an already-non-blocking stream.
    fn from_stream(stream: S) -> Self {
        ForwardConn {
            stream,
            out: Vec::new(),
            read_closed: false,
            peer_closed: false,
            fin_sent: false,
            dead: false,
            flush_stall: 0,
        }
    }

    /// Drain currently-available bytes from the socket (to forward into the
    /// session). Sets `read_closed` on EOF, `dead` on error.
    pub fn read_tcp(&mut self) -> Vec<u8> {
        let mut got = Vec::new();
        if self.read_closed || self.dead {
            return got;
        }
        let mut buf = [0u8; 16384];
        loop {
            match self.stream.read(&mut buf) {
                Ok(0) => {
                    self.read_closed = true;
                    break;
                }
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => {
                    self.dead = true;
                    break;
                }
            }
        }
        got
    }

    /// Queue bytes (from the session) to write to TCP, then try to flush.
    pub fn queue_to_tcp(&mut self, data: &[u8]) {
        self.out.extend_from_slice(data);
        self.flush();
    }

    /// Try to flush buffered bytes to the TCP socket (non-blocking).
    pub fn flush(&mut self) {
        while !self.out.is_empty() && !self.dead {
            match self.stream.write(&self.out) {
                Ok(0) => break,
                Ok(n) => {
                    self.out.drain(0..n);
                    self.flush_stall = 0; // progress
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    // TCP peer's receive buffer is full. Bound how long we wait
                    // for it to drain before declaring the connection dead, so a
                    // permanently-stuck peer can't leak the connection forever.
                    self.flush_stall = self.flush_stall.saturating_add(1);
                    if self.flush_stall >= FLUSH_STALL_LIMIT {
                        self.dead = true;
                        self.out.clear();
                    }
                    break;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => {
                    self.dead = true;
                    self.out.clear();
                    break;
                }
            }
        }
    }

    /// Record that the session peer closed its send half.
    pub fn mark_peer_closed(&mut self) {
        self.peer_closed = true;
    }

    /// True when our TCP read side closed and we still owe the peer a FIN.
    pub fn needs_fin(&mut self) -> bool {
        if self.read_closed && !self.fin_sent {
            self.fin_sent = true;
            true
        } else {
            false
        }
    }

    /// The connection is fully finished and can be reclaimed: either the TCP
    /// socket errored, or both directions closed and all buffered output has
    /// been written to TCP.
    pub fn is_finished(&self) -> bool {
        self.dead || (self.read_closed && self.peer_closed && self.out.is_empty())
    }

    /// Whether buffered output is waiting to be written (for POLLOUT interest).
    pub fn wants_write(&self) -> bool {
        !self.out.is_empty()
    }

    /// Bytes buffered toward the socket (so the driver can bound it and apply
    /// receive-side backpressure to the session peer).
    pub fn out_len(&self) -> usize {
        self.out.len()
    }

    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }

    pub fn as_raw_fd(&self) -> RawFd {
        use std::os::fd::AsRawFd;
        self.stream.as_fd().as_raw_fd()
    }
}
