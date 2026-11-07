//! QUIC plumbing shared by the client and server cores.
//!
//! - Endpoint and transport configuration (noissh's private QUIC version, the
//!   Noise crypto layer from `noise-quic`, flow-control windows, keep-alive).
//! - [`Streams`]: noissh's stream kinds (forward, exec, file transfer, agent)
//!   carried on QUIC bidirectional streams, with the byte-pipe API the drivers
//!   use (`open` / `write` / `read` / `close` / `reset`, lifecycle events).
//! - The control channel: the first bidirectional stream the client opens,
//!   carrying length-prefixed [`wire::Frame`]s (control messages, shell input,
//!   screen-state acks, and screen diffs too large for a datagram).
//!
//! Every stream starts with a header: one kind byte, a big-endian u16 metadata
//! length, then the metadata (a forward's target, an exec's command, a file
//! transfer request). Kind 0 marks the control stream.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use quinn_proto::{
    Connection, Dir, EndpointConfig, IdleTimeout, ReadError, StreamId, TransportConfig, VarInt,
    WriteError,
};
use wire::{Frame, StreamKind};

/// Identifies one client session on a server (one QUIC connection, plus the
/// shell it may keep while detached).
pub type SessionId = u64;

/// Stream lifecycle events surfaced to the drivers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    /// The peer opened a stream of `kind` with `meta` (its header).
    Opened {
        id: u64,
        kind: StreamKind,
        meta: Vec<u8>,
    },
    /// Data may be waiting to be read.
    Readable { id: u64 },
    /// The peer finished its send half and every byte has been read.
    Closed { id: u64 },
    /// The remote command on exec stream `id` exited with `status`.
    Exited { id: u64, status: i32 },
    /// The stream was aborted (by the peer, or because the connection ended).
    Reset { id: u64 },
}

/// Idle timeout of a connection: with the client's keep-alive every
/// [`KEEP_ALIVE`], a connection that hears nothing for this long is gone (the
/// client reconnects; the server keeps a detached shell for its grace period).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Client keep-alive interval: refreshes NAT mappings and lets the client
/// notice a dead path (the status banner) within a few seconds.
pub const KEEP_ALIVE: Duration = Duration::from_secs(3);

/// Per-stream receive window (how much one stream may have in flight).
/// Sized for a fast long path: 8 MiB covers 400 Mbit/s at 150 ms RTT.
const STREAM_WINDOW: u32 = 8 * 1024 * 1024;
/// Connection-wide receive and send windows.
const CONN_WINDOW: u32 = 32 * 1024 * 1024;
/// Concurrent streams each side may open (VS Code opens many short-lived
/// forwards through `-D`).
const MAX_STREAMS: u32 = 1024;
/// Bytes read from a stream per `read` call.
const MAX_READ: usize = 256 * 1024;
/// Largest control-channel message accepted.
const MAX_CONTROL_MSG: usize = 16 * 1024 * 1024;
/// Header kind byte of the control stream.
const KIND_CONTROL: u8 = 0;

/// Stream priorities: the control stream (keystrokes, acks, screen updates)
/// goes first, file transfers last.
const PRIO_CONTROL: i32 = 100;
const PRIO_XFER: i32 = -10;

/// The endpoint configuration both sides use: noissh's QUIC version and a
/// random stateless-reset key.
pub fn endpoint_config() -> Arc<EndpointConfig> {
    let mut cfg = EndpointConfig::new(Arc::new(noise_quic::Blake2sHmac::random()));
    cfg.supported_versions(vec![noise_quic::VERSION]);
    Arc::new(cfg)
}

/// Transport parameters. `idle` overrides [`IDLE_TIMEOUT`] (tests use short
/// ones); `keep_alive` is set on the client only.
pub fn transport_config(idle: Duration, keep_alive: Option<Duration>) -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.max_idle_timeout(IdleTimeout::try_from(idle).ok())
        .keep_alive_interval(keep_alive)
        .stream_receive_window(VarInt::from_u32(STREAM_WINDOW))
        .receive_window(VarInt::from_u32(CONN_WINDOW))
        .send_window(CONN_WINDOW as u64)
        .max_concurrent_bidi_streams(VarInt::from_u32(MAX_STREAMS))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .datagram_receive_buffer_size(Some(1024 * 1024))
        .datagram_send_buffer_size(1024 * 1024);
    // Ask the peer to acknowledge every 8th packet rather than every 2nd
    // (both ends are noissh, so the ACK-frequency extension is understood):
    // a quarter of the ACK datagrams during bulk transfers. Out-of-order
    // arrival still triggers an immediate ACK, so loss detection isn't slowed.
    let mut af = quinn_proto::AckFrequencyConfig::default();
    af.ack_eliciting_threshold(VarInt::from_u32(7))
        .reordering_threshold(VarInt::from_u32(2));
    t.ack_frequency_config(Some(af));
    // BBR by default: loss-based controllers (Cubic, NewReno) collapse on
    // paths with random loss (Wi-Fi, mobile), where noissh is meant to shine.
    // `NOISSH_CC=cubic` selects Cubic instead (for comparison, or a network
    // where BBR misbehaves).
    if std::env::var_os("NOISSH_CC").is_some_and(|v| v == "cubic") {
        t.congestion_controller_factory(Arc::new(quinn_proto::congestion::CubicConfig::default()));
    } else {
        t.congestion_controller_factory(Arc::new(quinn_proto::congestion::BbrConfig::default()));
    }
    Arc::new(t)
}

/// A 32-byte X25519 key from a key slice (noissh keys are always 32 bytes).
pub fn key32(k: &[u8]) -> Option<[u8; 32]> {
    k.try_into().ok()
}

/// The peer's authenticated static key, once the handshake has completed.
pub fn peer_key(conn: &Connection) -> Option<[u8; 32]> {
    conn.crypto_session()
        .peer_identity()
        .and_then(|b| b.downcast::<noise_quic::PeerIdentity>().ok())
        .map(|p| p.0)
}

fn to_sid(id: u64) -> StreamId {
    StreamId::from(VarInt::from_u64(id).unwrap_or(VarInt::MAX))
}

#[derive(Default)]
struct Entry {
    /// Header bytes read so far, while the peer's header is incomplete.
    header: Option<Vec<u8>>,
    /// Bytes accepted from the application, not yet taken by QUIC.
    tx: VecDeque<u8>,
    fin_pending: bool,
    fin_sent: bool,
    /// FIN read, or the stream was reset: nothing more to read.
    recv_done: bool,
    reset: bool,
}

/// The stream table of one connection. Every method that touches QUIC takes
/// the connection, so the table can live beside it.
pub struct Streams {
    is_server: bool,
    map: HashMap<u64, Entry>,
    events: Vec<StreamEvent>,
    control: Option<u64>,
    /// Inbound control bytes not yet parsed into frames.
    ctl_rx: Vec<u8>,
    /// Frames to send once the control stream exists.
    ctl_queue: Vec<Frame>,
    /// Frames received (control stream and datagrams).
    frames: Vec<Frame>,
    /// Ids handed out for streams that could not be opened (reported reset).
    next_dead: u64,
}

impl Streams {
    pub fn new(is_server: bool) -> Self {
        Streams {
            is_server,
            map: HashMap::new(),
            events: Vec::new(),
            control: None,
            ctl_rx: Vec::new(),
            ctl_queue: Vec::new(),
            frames: Vec::new(),
            next_dead: u64::MAX,
        }
    }

    /// Whether the control stream exists (client: opened; server: accepted).
    pub fn has_control(&self) -> bool {
        self.control.is_some()
    }

    /// Client: open the control stream (after the handshake), then send what
    /// was queued.
    pub fn open_control(&mut self, conn: &mut Connection) {
        if self.control.is_some() {
            return;
        }
        let Some(sid) = conn.streams().open(Dir::Bi) else {
            return;
        };
        let id = u64::from(sid);
        let _ = conn.send_stream(sid).set_priority(PRIO_CONTROL);
        let mut e = Entry::default();
        e.tx.extend([KIND_CONTROL, 0, 0]);
        self.map.insert(id, e);
        self.control = Some(id);
        for f in std::mem::take(&mut self.ctl_queue) {
            self.send_frame(conn, &f);
        }
    }

    /// Queue a frame on the control stream (or until it exists).
    pub fn send_frame(&mut self, conn: &mut Connection, f: &Frame) {
        let Some(id) = self.control else {
            self.ctl_queue.push(f.clone());
            return;
        };
        let body = wire::encode_frames(std::slice::from_ref(f));
        if let Some(e) = self.map.get_mut(&id) {
            e.tx.extend((body.len() as u32).to_be_bytes());
            e.tx.extend(body);
        }
        self.flush(conn);
    }

    /// Send a frame as a datagram if it fits, else on the control stream.
    /// Datagrams suit latest-wins data (screen diffs): a lost one is simply
    /// superseded or resent by the shell's own ack logic.
    pub fn send_datagram(&mut self, conn: &mut Connection, f: &Frame) {
        let body = wire::encode_frames(std::slice::from_ref(f));
        let fits = conn
            .datagrams()
            .max_size()
            .is_some_and(|max| body.len() <= max);
        if fits && conn.datagrams().send(Bytes::from(body), true).is_ok() {
            return;
        }
        self.send_frame(conn, f);
    }

    /// Bytes waiting on the control stream (to hold back bulky screen diffs
    /// while earlier ones are still queued).
    pub fn control_backlog(&self) -> usize {
        self.control
            .and_then(|id| self.map.get(&id))
            .map_or(0, |e| e.tx.len())
    }

    /// Frames received since the last call.
    pub fn take_frames(&mut self) -> Vec<Frame> {
        std::mem::take(&mut self.frames)
    }

    /// Stream events since the last call.
    pub fn take_events(&mut self) -> Vec<StreamEvent> {
        std::mem::take(&mut self.events)
    }

    /// Record an event the core generates itself (e.g. an exec's exit code).
    pub fn push_event(&mut self, ev: StreamEvent) {
        self.events.push(ev);
    }

    /// Open a stream of `kind` carrying `meta`. Returns its id; if no stream
    /// can be opened right now, the id is reported reset at once.
    pub fn open(&mut self, conn: Option<&mut Connection>, kind: StreamKind, meta: &[u8]) -> u64 {
        let opened = conn.and_then(|c| c.streams().open(Dir::Bi).map(|sid| (c, sid)));
        let Some((conn, sid)) = opened.filter(|_| meta.len() <= u16::MAX as usize) else {
            let id = self.next_dead;
            self.next_dead -= 1;
            self.events.push(StreamEvent::Reset { id });
            return id;
        };
        if kind == StreamKind::FileTransfer {
            let _ = conn.send_stream(sid).set_priority(PRIO_XFER);
        }
        let id = u64::from(sid);
        let mut e = Entry::default();
        e.tx.push_back(kind as u8);
        e.tx.extend((meta.len() as u16).to_be_bytes());
        e.tx.extend(meta);
        self.map.insert(id, e);
        self.flush(conn);
        id
    }

    pub fn write(&mut self, conn: Option<&mut Connection>, id: u64, data: &[u8]) {
        if let Some(e) = self.map.get_mut(&id)
            && !e.reset
            && !e.fin_pending
        {
            e.tx.extend(data);
        }
        if let Some(conn) = conn {
            self.flush(conn);
        }
    }

    /// Finish our send half once everything queued has gone out.
    pub fn close(&mut self, conn: Option<&mut Connection>, id: u64) {
        if let Some(e) = self.map.get_mut(&id) {
            e.fin_pending = true;
        }
        if let Some(conn) = conn {
            self.flush(conn);
        }
    }

    /// Abort both halves of a stream (or forget one the peer reset).
    pub fn reset(&mut self, conn: Option<&mut Connection>, id: u64) {
        if let Some(e) = self.map.remove(&id)
            && !e.reset
            && let Some(conn) = conn
        {
            let sid = to_sid(id);
            let _ = conn.send_stream(sid).reset(VarInt::from_u32(1));
            let _ = conn.recv_stream(sid).stop(VarInt::from_u32(1));
        }
    }

    /// Bytes written by the application and not yet taken by QUIC (driver
    /// backpressure: QUIC's own buffer is bounded by its send window).
    pub fn in_flight(&self, id: u64) -> u64 {
        self.map.get(&id).map_or(0, |e| e.tx.len() as u64)
    }

    /// True once the peer finished its half cleanly and everything has been
    /// read (or the stream no longer exists). False for a reset stream, which
    /// stays known (as reset) until the application calls [`Streams::reset`].
    pub fn recv_finished(&self, id: u64) -> bool {
        self.map.get(&id).is_none_or(|e| e.recv_done && !e.reset)
    }

    /// Read what is available on a stream (up to [`MAX_READ`] bytes).
    pub fn read(&mut self, conn: Option<&mut Connection>, id: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let Some(conn) = conn else {
            return out;
        };
        let Some(e) = self.map.get_mut(&id) else {
            return out;
        };
        if e.header.is_some() || e.recv_done {
            return out;
        }
        let mut rs = conn.recv_stream(to_sid(id));
        match rs.read(true) {
            Ok(mut chunks) => {
                while out.len() < MAX_READ {
                    match chunks.next(MAX_READ - out.len()) {
                        Ok(Some(c)) => out.extend_from_slice(&c.bytes),
                        Ok(None) => {
                            e.recv_done = true;
                            self.events.push(StreamEvent::Closed { id });
                            break;
                        }
                        Err(ReadError::Blocked) => break,
                        Err(ReadError::Reset(_)) => {
                            e.recv_done = true;
                            e.reset = true;
                            e.tx.clear();
                            self.events.push(StreamEvent::Reset { id });
                            break;
                        }
                    }
                }
                let _ = chunks.finalize();
            }
            Err(_) => e.recv_done = true,
        }
        if e.reset {
            // The peer aborted: stop our half too.
            let _ = conn.send_stream(to_sid(id)).reset(VarInt::from_u32(1));
        }
        self.gc(id);
        out
    }

    /// Push queued bytes (and pending FINs) into QUIC, as flow control allows.
    pub fn flush(&mut self, conn: &mut Connection) {
        let mut done = Vec::new();
        for (&id, e) in self.map.iter_mut() {
            if e.reset || e.fin_sent || (e.tx.is_empty() && !e.fin_pending) {
                continue;
            }
            let mut ss = conn.send_stream(to_sid(id));
            while !e.tx.is_empty() {
                let (a, _) = e.tx.as_slices();
                match ss.write(a) {
                    Ok(0) | Err(WriteError::Blocked) => break,
                    Ok(n) => {
                        e.tx.drain(..n);
                    }
                    Err(_) => {
                        // Stopped by the peer, or gone.
                        e.tx.clear();
                        e.fin_sent = true;
                        break;
                    }
                }
            }
            if e.tx.is_empty() && e.fin_pending && !e.fin_sent {
                let _ = ss.finish();
                e.fin_sent = true;
            }
            if e.fin_sent && e.recv_done {
                done.push(id);
            }
        }
        for id in done {
            self.gc(id);
        }
    }

    fn gc(&mut self, id: u64) {
        if Some(id) == self.control {
            return;
        }
        if let Some(e) = self.map.get(&id)
            && e.recv_done
            && e.fin_sent
            && !e.reset
            && e.tx.is_empty()
        {
            self.map.remove(&id);
        }
    }

    /// Feed a QUIC stream event.
    pub fn on_event(&mut self, conn: &mut Connection, ev: quinn_proto::StreamEvent) {
        use quinn_proto::StreamEvent as Q;
        match ev {
            Q::Opened { dir: Dir::Bi } => {
                while let Some(sid) = conn.streams().accept(Dir::Bi) {
                    let id = u64::from(sid);
                    self.map.insert(
                        id,
                        Entry {
                            header: Some(Vec::new()),
                            ..Entry::default()
                        },
                    );
                    self.read_header(conn, id);
                }
            }
            Q::Opened { dir: Dir::Uni } => {
                while let Some(sid) = conn.streams().accept(Dir::Uni) {
                    let _ = conn.recv_stream(sid).stop(VarInt::from_u32(1));
                }
            }
            Q::Readable { id: sid } => {
                let id = u64::from(sid);
                if Some(id) == self.control {
                    self.read_control(conn);
                } else if self.map.get(&id).is_some_and(|e| e.header.is_some()) {
                    self.read_header(conn, id);
                } else if self.map.contains_key(&id) {
                    self.events.push(StreamEvent::Readable { id });
                }
            }
            Q::Writable { .. } => self.flush(conn),
            Q::Stopped { id: sid, .. } => {
                let id = u64::from(sid);
                if let Some(e) = self.map.get_mut(&id)
                    && !e.reset
                {
                    e.reset = true;
                    e.recv_done = true;
                    e.tx.clear();
                    self.events.push(StreamEvent::Reset { id });
                    let _ = conn.send_stream(sid).reset(VarInt::from_u32(1));
                    let _ = conn.recv_stream(sid).stop(VarInt::from_u32(1));
                }
            }
            _ => {}
        }
    }

    /// The connection is gone: every open stream is reset.
    pub fn fail_all(&mut self) {
        for (id, e) in self.map.drain() {
            if !e.recv_done || !e.fin_sent {
                self.events.push(StreamEvent::Reset { id });
            }
        }
        self.control = None;
    }

    fn read_header(&mut self, conn: &mut Connection, id: u64) {
        let Some(e) = self.map.get_mut(&id) else {
            return;
        };
        let Some(hdr) = e.header.as_mut() else {
            return;
        };
        let mut rs = conn.recv_stream(to_sid(id));
        let mut bad = false;
        if let Ok(mut chunks) = rs.read(true) {
            loop {
                let need = if hdr.len() < 3 {
                    3 - hdr.len()
                } else {
                    3 + u16::from_be_bytes([hdr[1], hdr[2]]) as usize - hdr.len()
                };
                if need == 0 {
                    break;
                }
                match chunks.next(need) {
                    Ok(Some(c)) => hdr.extend_from_slice(&c.bytes),
                    Ok(None) | Err(ReadError::Reset(_)) => {
                        bad = true;
                        break;
                    }
                    Err(ReadError::Blocked) => break,
                }
            }
            let _ = chunks.finalize();
        }
        let complete =
            hdr.len() >= 3 && hdr.len() == 3 + u16::from_be_bytes([hdr[1], hdr[2]]) as usize;
        if bad {
            self.reset(Some(conn), id);
            return;
        }
        if !complete {
            return;
        }
        let hdr = e.header.take().unwrap_or_default();
        if hdr[0] == KIND_CONTROL {
            if self.is_server && self.control.is_none() {
                self.control = Some(id);
                let _ = conn.send_stream(to_sid(id)).set_priority(PRIO_CONTROL);
                for f in std::mem::take(&mut self.ctl_queue) {
                    self.send_frame(conn, &f);
                }
                self.read_control(conn);
            } else {
                self.reset(Some(conn), id);
            }
            return;
        }
        match StreamKind::from_u8(hdr[0]) {
            Some(kind) => {
                self.events.push(StreamEvent::Opened {
                    id,
                    kind,
                    meta: hdr[3..].to_vec(),
                });
                // Data may have arrived with the header; no further Readable
                // event will announce it.
                self.events.push(StreamEvent::Readable { id });
            }
            None => self.reset(Some(conn), id),
        }
    }

    fn read_control(&mut self, conn: &mut Connection) {
        let Some(id) = self.control else {
            return;
        };
        let mut rs = conn.recv_stream(to_sid(id));
        if let Ok(mut chunks) = rs.read(true) {
            while let Ok(Some(c)) = chunks.next(usize::MAX) {
                self.ctl_rx.extend_from_slice(&c.bytes);
            }
            let _ = chunks.finalize();
        }
        let mut pos = 0;
        while self.ctl_rx.len() - pos >= 4 {
            let n = u32::from_be_bytes(self.ctl_rx[pos..pos + 4].try_into().unwrap()) as usize;
            if n > MAX_CONTROL_MSG {
                // A broken peer: drop the channel.
                self.ctl_rx.clear();
                return;
            }
            if self.ctl_rx.len() - pos - 4 < n {
                break;
            }
            if let Ok(fs) = wire::decode_frames(&self.ctl_rx[pos + 4..pos + 4 + n]) {
                self.frames.extend(fs);
            }
            pos += 4 + n;
        }
        self.ctl_rx.drain(..pos);
    }

    /// Collect received datagrams as frames.
    pub fn read_datagrams(&mut self, conn: &mut Connection) {
        while let Some(d) = conn.datagrams().recv() {
            if let Ok(fs) = wire::decode_frames(&d) {
                self.frames.extend(fs);
            }
        }
    }
}

/// Drain a connection's outgoing datagrams.
pub fn drain_transmits(
    conn: &mut Connection,
    now: std::time::Instant,
) -> Vec<(std::net::SocketAddr, Vec<u8>)> {
    let mut out = Vec::new();
    let mut buf = Vec::new();
    while let Some(t) = conn.poll_transmit(now, 1, &mut buf) {
        out.push((t.destination, buf[..t.size].to_vec()));
        buf.clear();
    }
    out
}
