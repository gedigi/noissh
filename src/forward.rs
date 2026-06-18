//! TCP plumbing for port forwarding: pairs a non-blocking [`TcpStream`] with a
//! reliable session stream, buffering each direction so neither side blocks.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;

/// One forwarded TCP connection. The session-stream side is driven by the
/// caller (read via the mux, write via the mux); this type owns the TCP socket
/// and an outbound buffer for bytes arriving from the session.
pub struct ForwardConn {
    stream: TcpStream,
    /// Bytes received from the session, waiting to be written to TCP.
    out: Vec<u8>,
    /// The TCP peer closed its side (read returned EOF) or errored.
    tcp_closed: bool,
}

impl ForwardConn {
    pub fn new(stream: TcpStream) -> std::io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(ForwardConn {
            stream,
            out: Vec::new(),
            tcp_closed: false,
        })
    }

    /// Connect out to `target` ("host:port"), returning a non-blocking conn.
    pub fn connect(target: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(target)?;
        ForwardConn::new(stream)
    }

    /// Drain all currently-available bytes from the TCP socket (to forward into
    /// the session). Sets `tcp_closed` on EOF/error.
    pub fn read_tcp(&mut self) -> Vec<u8> {
        let mut got = Vec::new();
        let mut buf = [0u8; 16384];
        loop {
            match self.stream.read(&mut buf) {
                Ok(0) => {
                    self.tcp_closed = true;
                    break;
                }
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => {
                    self.tcp_closed = true;
                    break;
                }
            }
        }
        got
    }

    /// Queue bytes (from the session) to be written to TCP, then try to flush.
    pub fn queue_to_tcp(&mut self, data: &[u8]) {
        self.out.extend_from_slice(data);
        self.flush();
    }

    /// Try to flush buffered bytes to the TCP socket (non-blocking).
    pub fn flush(&mut self) {
        while !self.out.is_empty() {
            match self.stream.write(&self.out) {
                Ok(0) => break,
                Ok(n) => {
                    self.out.drain(0..n);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => {
                    self.tcp_closed = true;
                    self.out.clear();
                    break;
                }
            }
        }
    }

    /// The TCP peer has closed and all buffered output has been written.
    pub fn is_done(&self) -> bool {
        self.tcp_closed && self.out.is_empty()
    }

    pub fn tcp_closed(&self) -> bool {
        self.tcp_closed
    }

    /// Raw fd for poll registration.
    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.stream.as_raw_fd()
    }
}
