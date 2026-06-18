//! Minimal SOCKS proxy front-end for dynamic forwarding (`-D`).
//!
//! A local TCP connection from a SOCKS client is negotiated here (SOCKS5 with
//! no-auth, plus SOCKS4/4a `CONNECT`); once the target `host:port` is known we
//! reply success and hand the socket off to the normal forwarding bridge, which
//! tunnels it to the server as a `Forward` stream. Only `CONNECT` is supported
//! (no `BIND`/`UDP ASSOCIATE`), matching typical `-D` usage.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsFd, BorrowedFd};

/// Upper bound on buffered negotiation bytes before a connection is rejected as
/// malformed (the longest valid SOCKS4a request is ~520 bytes).
const MAX_NEGOTIATION_BYTES: usize = 600;

/// Negotiation state of one accepted SOCKS connection.
enum Phase {
    /// SOCKS5: awaiting the method-selection greeting.
    Greeting,
    /// SOCKS5: greeting done, awaiting the CONNECT request.
    Request,
    /// Target parsed; success reply queued/sent.
    Done,
    /// Unsupported/garbled request; the connection will be dropped.
    Failed,
}

/// Result of driving a [`SocksConn`] one step.
pub enum Progress {
    /// Still negotiating; call again when the socket is readable.
    Pending,
    /// CONNECT target parsed and the success reply has been sent. The caller
    /// should open a forward stream to `target` and bridge `socket`, writing any
    /// `leftover` bytes (early application data) into the stream first.
    Connected {
        target: String,
        socket: TcpStream,
        leftover: Vec<u8>,
    },
    /// Negotiation failed; drop the connection.
    Failed,
}

/// One in-progress SOCKS negotiation over a non-blocking TCP socket.
pub struct SocksConn {
    stream: TcpStream,
    inbuf: Vec<u8>,
    out: Vec<u8>,
    phase: Phase,
    target: Option<String>,
}

impl SocksConn {
    pub fn new(stream: TcpStream) -> std::io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(SocksConn {
            stream,
            inbuf: Vec::new(),
            out: Vec::new(),
            phase: Phase::Greeting,
            target: None,
        })
    }

    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }

    /// Drive negotiation: read what's available, advance the state machine, and
    /// flush any reply. Returns whether the connection is ready, pending, or
    /// failed.
    pub fn negotiate(mut self) -> (Progress, Option<SocksConn>) {
        // `self` is consumed so a `Connected`/`Failed` result can move the socket
        // out; on `Pending` we hand `self` back to the caller to retry later.
        self.flush_out();
        if matches!(self.phase, Phase::Failed) {
            return (Progress::Failed, None);
        }
        // Drain readable bytes.
        let mut buf = [0u8; 1024];
        loop {
            match self.stream.read(&mut buf) {
                Ok(0) => {
                    return (Progress::Failed, None); // peer closed mid-negotiation
                }
                Ok(n) => self.inbuf.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return (Progress::Failed, None),
            }
        }
        // Bound the negotiation buffer: the largest valid request (SOCKS4a with
        // max userid + hostname) is well under 600 bytes, so anything larger is
        // a malformed/stalling client. This also caps a peer that never sends a
        // terminating NUL.
        if self.inbuf.len() > MAX_NEGOTIATION_BYTES {
            return (Progress::Failed, None);
        }
        self.try_parse();
        self.flush_out();
        match self.phase {
            Phase::Failed => (Progress::Failed, None),
            Phase::Done if self.out.is_empty() => {
                let target = self.target.take().unwrap_or_default();
                (
                    Progress::Connected {
                        target,
                        socket: self.stream,
                        leftover: self.inbuf,
                    },
                    None,
                )
            }
            _ => (Progress::Pending, Some(self)),
        }
    }

    /// Push queued reply bytes to the socket (best-effort, non-blocking).
    fn flush_out(&mut self) {
        while !self.out.is_empty() {
            match self.stream.write(&self.out) {
                Ok(0) => break,
                Ok(n) => {
                    self.out.drain(0..n);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => {
                    self.phase = Phase::Failed;
                    break;
                }
            }
        }
    }

    /// Advance the parser over whatever is currently buffered.
    fn try_parse(&mut self) {
        loop {
            match self.phase {
                Phase::Greeting => {
                    let Some(&ver) = self.inbuf.first() else {
                        return;
                    };
                    match ver {
                        5 => {
                            // [ver, nmethods, methods...]
                            let Some(&n) = self.inbuf.get(1) else { return };
                            if n == 0 {
                                self.phase = Phase::Failed; // no methods offered
                                return;
                            }
                            let total = 2 + n as usize;
                            if self.inbuf.len() < total {
                                return;
                            }
                            self.inbuf.drain(0..total);
                            // Reply: version 5, method 0 (no authentication).
                            self.out.extend_from_slice(&[0x05, 0x00]);
                            self.phase = Phase::Request;
                        }
                        4 => {
                            // SOCKS4 is a single message; parse it directly.
                            self.parse_socks4();
                            return;
                        }
                        _ => {
                            self.phase = Phase::Failed;
                            return;
                        }
                    }
                }
                Phase::Request => {
                    if !self.parse_socks5_request() {
                        return;
                    }
                }
                Phase::Done | Phase::Failed => return,
            }
        }
    }

    /// Parse a SOCKS5 CONNECT request. Returns true once consumed (phase moved
    /// to Done/Failed), false if more bytes are needed.
    fn parse_socks5_request(&mut self) -> bool {
        // [ver, cmd, rsv, atyp, addr.., port(2)]
        if self.inbuf.len() < 4 {
            return false;
        }
        let (ver, cmd, atyp) = (self.inbuf[0], self.inbuf[1], self.inbuf[3]);
        if ver != 5 {
            self.fail_socks5(0x01);
            return true;
        }
        let (addr_len, addr_start) = match atyp {
            0x01 => (4usize, 4usize),  // IPv4
            0x04 => (16usize, 4usize), // IPv6
            0x03 => {
                let Some(&l) = self.inbuf.get(4) else {
                    return false;
                };
                (l as usize, 5usize)
            }
            _ => {
                self.fail_socks5(0x08); // address type not supported
                return true;
            }
        };
        let need = addr_start + addr_len + 2;
        if self.inbuf.len() < need {
            return false;
        }
        if cmd != 0x01 {
            self.fail_socks5(0x07); // command not supported (only CONNECT)
            return true;
        }
        let addr = &self.inbuf[addr_start..addr_start + addr_len];
        let port_bytes = &self.inbuf[addr_start + addr_len..need];
        let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
        let host = match atyp {
            0x01 => format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]),
            0x04 => {
                let mut seg = [0u16; 8];
                for (i, s) in seg.iter_mut().enumerate() {
                    *s = u16::from_be_bytes([addr[i * 2], addr[i * 2 + 1]]);
                }
                std::net::Ipv6Addr::new(
                    seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
                )
                .to_string()
            }
            _ => match std::str::from_utf8(addr) {
                Ok(s) => s.to_string(),
                Err(_) => {
                    self.fail_socks5(0x01);
                    return true;
                }
            },
        };
        self.inbuf.drain(0..need);
        // Success reply: ver 5, rep 0, rsv, atyp ipv4, BND 0.0.0.0:0.
        self.out
            .extend_from_slice(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        let target = if atyp == 0x04 {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        self.target = Some(target);
        self.phase = Phase::Done;
        true
    }

    /// Queue a SOCKS5 failure reply and mark the connection failed.
    fn fail_socks5(&mut self, rep: u8) {
        self.out
            .extend_from_slice(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        self.phase = Phase::Failed;
    }

    /// Parse a SOCKS4/4a CONNECT request: [4, cmd, port(2), ip(4), userid, 0x00,
    /// (host, 0x00 for 4a)].
    fn parse_socks4(&mut self) {
        if self.inbuf.len() < 9 {
            return; // need at least the fixed header + the userid terminator
        }
        let cmd = self.inbuf[1];
        let port = u16::from_be_bytes([self.inbuf[2], self.inbuf[3]]);
        let ip = [self.inbuf[4], self.inbuf[5], self.inbuf[6], self.inbuf[7]];
        // The all-zero IP is not a valid destination (and isn't the 0.0.0.x
        // SOCKS4a marker); reject rather than forward to 0.0.0.0.
        if ip == [0, 0, 0, 0] {
            self.fail_socks4();
            return;
        }
        // userid is NUL-terminated starting at offset 8.
        let Some(uid_nul) = self.inbuf[8..].iter().position(|&b| b == 0).map(|p| p + 8) else {
            return; // userid not fully received yet
        };
        // SOCKS4a: IP 0.0.0.x (x != 0) means a hostname follows the userid.
        let is_4a = ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0;
        let (host, consumed) = if is_4a {
            let host_start = uid_nul + 1;
            let Some(host_nul) = self.inbuf[host_start..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| p + host_start)
            else {
                return; // hostname not fully received yet
            };
            let host = match std::str::from_utf8(&self.inbuf[host_start..host_nul]) {
                Ok(s) => s.to_string(),
                Err(_) => {
                    self.fail_socks4();
                    return;
                }
            };
            (host, host_nul + 1)
        } else {
            (
                format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
                uid_nul + 1,
            )
        };
        if cmd != 0x01 {
            self.fail_socks4();
            return;
        }
        self.inbuf.drain(0..consumed);
        // Granted reply: VN 0, CD 0x5A, then port + ip echoed back.
        let mut reply = vec![0x00, 0x5A];
        reply.extend_from_slice(&port.to_be_bytes());
        reply.extend_from_slice(&ip);
        self.out.extend_from_slice(&reply);
        self.target = Some(format!("{host}:{port}"));
        self.phase = Phase::Done;
    }

    fn fail_socks4(&mut self) {
        // VN 0, CD 0x5B (request rejected/failed), then zeros.
        self.out.extend_from_slice(&[0x00, 0x5B, 0, 0, 0, 0, 0, 0]);
        self.phase = Phase::Failed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    /// A connected loopback TCP pair (client end, server end).
    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = l.accept().unwrap();
        (client, server)
    }

    /// Drive a SocksConn to a terminal result, retrying while it's pending.
    fn drive(mut sc: SocksConn) -> Progress {
        for _ in 0..100 {
            match sc.negotiate() {
                (Progress::Pending, Some(c)) => {
                    sc = c;
                    std::thread::sleep(Duration::from_millis(2));
                }
                (p, _) => return p,
            }
        }
        Progress::Failed
    }

    #[test]
    fn socks5_domain_connect() {
        let (mut client, server) = pair();
        let sc = SocksConn::new(server).unwrap();
        client.write_all(&[5, 1, 0]).unwrap();
        let host = b"example.com";
        let mut req = vec![5, 1, 0, 3, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).unwrap();
        match drive(sc) {
            Progress::Connected { target, .. } => assert_eq!(target, "example.com:443"),
            _ => panic!("expected a Connected result"),
        }
    }

    #[test]
    fn socks5_ipv4_connect() {
        let (mut client, server) = pair();
        let sc = SocksConn::new(server).unwrap();
        client.write_all(&[5, 1, 0]).unwrap();
        let mut req = vec![5, 1, 0, 1, 10, 0, 0, 7];
        req.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&req).unwrap();
        match drive(sc) {
            Progress::Connected { target, .. } => assert_eq!(target, "10.0.0.7:80"),
            _ => panic!("expected a Connected result"),
        }
    }

    #[test]
    fn socks4a_hostname_connect() {
        let (mut client, server) = pair();
        let sc = SocksConn::new(server).unwrap();
        // VER4, CONNECT, port, 0.0.0.1 (=> 4a), userid "", NUL, host, NUL.
        let mut req = vec![4, 1];
        req.extend_from_slice(&8080u16.to_be_bytes());
        req.extend_from_slice(&[0, 0, 0, 1]); // 0.0.0.x marks SOCKS4a
        req.push(0); // empty userid terminator
        req.extend_from_slice(b"example.org");
        req.push(0); // host terminator
        client.write_all(&req).unwrap();
        match drive(sc) {
            Progress::Connected { target, .. } => assert_eq!(target, "example.org:8080"),
            _ => panic!("expected a Connected result"),
        }
    }

    #[test]
    fn socks5_bind_command_is_rejected() {
        let (mut client, server) = pair();
        let sc = SocksConn::new(server).unwrap();
        client.write_all(&[5, 1, 0]).unwrap();
        // CMD 2 = BIND (unsupported).
        let mut req = vec![5, 2, 0, 1, 127, 0, 0, 1];
        req.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&req).unwrap();
        assert!(matches!(drive(sc), Progress::Failed));
    }
}
