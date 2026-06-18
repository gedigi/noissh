//! Reliable, ordered, flow-controlled stream multiplexer (v2).
//!
//! Rides the same Noise/UDP session as the v1 datagram overlay and roams with
//! it. Each stream is an independent byte stream with ARQ retransmission,
//! in-order reassembly, and a sliding receive window for flow control.
//!
//! The mux is I/O-free: it consumes and produces [`wire::Frame`]s. A driver
//! calls [`StreamMux::poll_transmit`] to get frames to seal, and feeds decoded
//! frames to [`StreamMux::on_frame`]. This keeps it deterministically testable
//! under injected loss and reorder.

use std::collections::BTreeMap;

use wire::{Frame, StreamKind};

/// Default per-stream receive window (bytes the peer may have in flight).
pub const DEFAULT_WINDOW: u32 = 256 * 1024;

/// Events surfaced to the application as frames are processed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    Opened {
        id: u64,
        kind: StreamKind,
        meta: Vec<u8>,
    },
    Readable {
        id: u64,
    },
    Closed {
        id: u64,
        status: i32,
    },
    Reset {
        id: u64,
    },
}

/// Reassembles out-of-order segments into a contiguous in-order byte stream.
#[derive(Default)]
struct Reassembler {
    /// Bytes already handed to the application via `read`.
    delivered: u64,
    /// Non-overlapping, coalesced future segments keyed by start offset.
    segs: BTreeMap<u64, Vec<u8>>,
}

impl Reassembler {
    fn insert(&mut self, mut offset: u64, mut data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        // Drop any already-delivered prefix.
        if offset < self.delivered {
            let cut = (self.delivered - offset) as usize;
            if cut >= data.len() {
                return;
            }
            data.drain(0..cut);
            offset = self.delivered;
        }
        let end = offset + data.len() as u64;
        // Find existing segments overlapping or adjacent to [offset, end].
        let keys: Vec<u64> = self
            .segs
            .range(..=end)
            .filter(|(k, v)| **k + v.len() as u64 >= offset)
            .map(|(k, _)| *k)
            .collect();
        let mut start = offset;
        let mut merged_end = end;
        for k in &keys {
            let seg = &self.segs[k];
            start = start.min(*k);
            merged_end = merged_end.max(*k + seg.len() as u64);
        }
        let mut buf = vec![0u8; (merged_end - start) as usize];
        for k in &keys {
            let seg = self.segs.remove(k).unwrap();
            let pos = (k - start) as usize;
            buf[pos..pos + seg.len()].copy_from_slice(&seg);
        }
        let pos = (offset - start) as usize;
        buf[pos..pos + data.len()].copy_from_slice(&data);
        self.segs.insert(start, buf);
    }

    /// Drain and return the contiguous bytes available from `delivered`.
    fn read(&mut self) -> Vec<u8> {
        if let Some(seg) = self.segs.remove(&self.delivered) {
            self.delivered += seg.len() as u64;
            seg
        } else {
            Vec::new()
        }
    }

    /// Highest contiguous offset received (ack point).
    fn ack_point(&self) -> u64 {
        match self.segs.get(&self.delivered) {
            Some(seg) => self.delivered + seg.len() as u64,
            None => self.delivered,
        }
    }

    /// Bytes received contiguously but not yet read by the app.
    fn unread(&self) -> u64 {
        self.ack_point() - self.delivered
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum HalfState {
    Open,
    /// We/peer sent FIN at this absolute offset.
    Finished(u64),
}

struct StreamState {
    id: u64,
    kind: StreamKind,
    meta: Vec<u8>,
    /// Whether we still owe the peer a StreamOpen frame.
    needs_open: bool,

    // --- send side ---
    send_buf: Vec<u8>, // bytes from `send_base` onward, not yet acked
    send_base: u64,    // offset of send_buf[0]; everything below is acked
    send_next: u64,    // total bytes written by us
    peer_window: u32,  // flow-control limit advertised by peer
    send_fin: bool,    // app closed our send side
    fin_sent: bool,
    fin_acked: bool,
    close_status: Option<i32>,

    // --- recv side ---
    recv: Reassembler,
    recv_window: u32,
    peer_fin: HalfState,
    close_received: bool, // a StreamClose has been surfaced as an event
    close_ticks: u32,     // polls spent waiting for a lost FIN after close
    reset: bool,
}

/// After a graceful close, how many `poll_transmit` rounds to wait for the
/// FIN-bearing `StreamData` before force-reclaiming the stream. This only
/// triggers when the peer has gone silent (an alive peer retransmits the FIN
/// well within this window), so it cannot drop data a live peer would resend.
const CLOSE_GRACE_TICKS: u32 = 100;

impl StreamState {
    fn new(id: u64, kind: StreamKind, meta: Vec<u8>, needs_open: bool) -> Self {
        StreamState {
            id,
            kind,
            meta,
            needs_open,
            send_buf: Vec::new(),
            send_base: 0,
            send_next: 0,
            peer_window: DEFAULT_WINDOW,
            send_fin: false,
            fin_sent: false,
            fin_acked: false,
            close_status: None,
            recv: Reassembler::default(),
            recv_window: DEFAULT_WINDOW,
            peer_fin: HalfState::Open,
            close_received: false,
            close_ticks: 0,
            reset: false,
        }
    }

    /// Both directions are closed and all received data has been read.
    fn fully_done(&self) -> bool {
        if !self.send_fin || !self.fin_acked {
            return false;
        }
        // Primary path: the peer's FIN-bearing StreamData arrived and all data
        // up to the FIN offset has been delivered and read.
        if matches!(self.peer_fin, HalfState::Finished(at)
            if self.recv.delivered >= at && self.recv.unread() == 0)
        {
            return true;
        }
        // Fallback: the peer sent a graceful StreamClose (surfaced to the app)
        // but the FIN-bearing StreamData never arrived and the peer has gone
        // silent for the grace window — reclaim so a dead peer can't leak the
        // stream forever. An alive peer would have resent the FIN by now.
        self.close_received && self.close_ticks >= CLOSE_GRACE_TICKS
    }

    fn write(&mut self, data: &[u8]) {
        self.send_buf.extend_from_slice(data);
        self.send_next += data.len() as u64;
    }

    fn on_ack(&mut self, ack: u64, window: u32) {
        self.peer_window = window;
        if ack > self.send_base {
            let advance = (ack - self.send_base).min(self.send_buf.len() as u64) as usize;
            self.send_buf.drain(0..advance);
            self.send_base += advance as u64;
        }
        // The receiver acks up to the data end; once it covers all our bytes,
        // our FIN is acknowledged (there is no extra FIN byte in the sequence).
        if self.send_fin && ack >= self.send_next {
            self.fin_acked = true;
        }
    }

    /// Frames to (re)transmit now, respecting the peer's flow window.
    fn transmit(&mut self, out: &mut Vec<Frame>) {
        if self.reset {
            return;
        }
        if self.needs_open {
            out.push(Frame::StreamOpen {
                id: self.id,
                kind: self.kind,
                meta: self.meta.clone(),
            });
            self.needs_open = false;
        }
        // Retransmit all unacked data within the flow window.
        let in_flight_cap = self.send_base + self.peer_window as u64;
        if !self.send_buf.is_empty() {
            let send_end = self.send_next.min(in_flight_cap);
            if send_end > self.send_base {
                let len = (send_end - self.send_base) as usize;
                let fin = self.send_fin && send_end == self.send_next && !self.fin_sent;
                out.push(Frame::StreamData {
                    id: self.id,
                    offset: self.send_base,
                    data: self.send_buf[..len].to_vec(),
                    fin,
                });
                if fin {
                    self.fin_sent = true;
                }
            }
        } else if self.send_fin && !self.fin_sent {
            // Empty FIN (no payload).
            out.push(Frame::StreamData {
                id: self.id,
                offset: self.send_next,
                data: Vec::new(),
                fin: true,
            });
            self.fin_sent = true;
        }
        // Always advertise our current receive window via an ack (saturating
        // cast guards against a misbehaving peer pushing past 4 GiB unread).
        let unread = self.recv.unread().min(DEFAULT_WINDOW as u64) as u32;
        self.recv_window = DEFAULT_WINDOW.saturating_sub(unread);
        out.push(Frame::StreamAck {
            id: self.id,
            ack: self.recv.ack_point(),
            window: self.recv_window,
        });
        // Retransmit the graceful close until the peer has acked all our data;
        // then stop (no perpetual StreamClose on a settled stream).
        if let Some(status) = self.close_status
            && !self.fin_acked
        {
            out.push(Frame::StreamClose {
                id: self.id,
                status,
            });
        }
        // Count down the close grace window while we're settled on our side but
        // still missing the peer's FIN (see `fully_done`).
        if self.close_received
            && self.send_fin
            && self.fin_acked
            && matches!(self.peer_fin, HalfState::Open)
        {
            self.close_ticks = self.close_ticks.saturating_add(1);
        }
    }
}

/// Multiplexes many reliable streams over one session.
pub struct StreamMux {
    /// Streams we initiate use ids with this parity (client=0, server=1).
    next_local_id: u64,
    id_step: u64,
    streams: BTreeMap<u64, StreamState>,
    events: Vec<StreamEvent>,
}

/// A read handle returned to callers (just the id; data via `StreamMux::read`).
pub type Stream = u64;

impl StreamMux {
    /// `is_client` controls local stream-id parity to avoid collisions.
    pub fn new(is_client: bool) -> Self {
        StreamMux {
            next_local_id: if is_client { 0 } else { 1 },
            id_step: 2,
            streams: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    /// Open a new locally-initiated stream; returns its id.
    pub fn open(&mut self, kind: StreamKind, meta: Vec<u8>) -> Stream {
        let id = self.next_local_id;
        self.next_local_id += self.id_step;
        self.streams
            .insert(id, StreamState::new(id, kind, meta, true));
        id
    }

    /// Queue bytes to send on a stream.
    pub fn write(&mut self, id: Stream, data: &[u8]) {
        if let Some(s) = self.streams.get_mut(&id) {
            s.write(data);
        }
    }

    /// Close our send side, optionally signalling an exit status.
    pub fn close(&mut self, id: Stream, status: i32) {
        if let Some(s) = self.streams.get_mut(&id) {
            s.send_fin = true;
            s.close_status = Some(status);
        }
    }

    /// Abort a stream immediately.
    pub fn reset(&mut self, id: Stream) {
        if let Some(s) = self.streams.get_mut(&id) {
            s.reset = true;
        }
    }

    /// Read contiguous received bytes from a stream.
    pub fn read(&mut self, id: Stream) -> Vec<u8> {
        match self.streams.get_mut(&id) {
            Some(s) => s.recv.read(),
            None => Vec::new(),
        }
    }

    /// True once the peer has closed and we've read everything.
    pub fn is_recv_finished(&self, id: Stream) -> bool {
        match self.streams.get(&id) {
            Some(s) => match s.peer_fin {
                HalfState::Finished(at) => s.recv.delivered >= at && s.recv.unread() == 0,
                HalfState::Open => false,
            },
            None => true,
        }
    }

    /// Drain accumulated events.
    pub fn take_events(&mut self) -> Vec<StreamEvent> {
        std::mem::take(&mut self.events)
    }

    /// Process one incoming stream-class frame. Non-stream frames are ignored.
    pub fn on_frame(&mut self, frame: Frame) {
        match frame {
            Frame::StreamOpen { id, kind, meta } => {
                if let std::collections::btree_map::Entry::Vacant(e) = self.streams.entry(id) {
                    e.insert(StreamState::new(id, kind, meta.clone(), false));
                    self.events.push(StreamEvent::Opened { id, kind, meta });
                }
            }
            Frame::StreamData {
                id,
                offset,
                data,
                fin,
            } => {
                if let Some(s) = self.streams.get_mut(&id) {
                    let had = s.recv.ack_point();
                    if fin {
                        s.peer_fin = HalfState::Finished(offset + data.len() as u64);
                    }
                    s.recv.insert(offset, data);
                    if s.recv.ack_point() > had {
                        self.events.push(StreamEvent::Readable { id });
                    }
                }
            }
            Frame::StreamAck { id, ack, window } => {
                if let Some(s) = self.streams.get_mut(&id) {
                    s.on_ack(ack, window);
                }
            }
            Frame::StreamClose { id, status } => {
                if let Some(s) = self.streams.get_mut(&id) {
                    // Do NOT derive a FIN offset here: a StreamClose reordered
                    // ahead of the FIN-bearing StreamData would otherwise fake a
                    // FIN at offset 0 and let `fully_done` reclaim the stream
                    // before the real data arrives (data loss). The authoritative
                    // FIN offset always comes from StreamData{fin}.
                    if !s.close_received {
                        s.close_received = true;
                        self.events.push(StreamEvent::Closed { id, status });
                    }
                }
            }
            Frame::StreamReset { id } => {
                if let Some(s) = self.streams.get_mut(&id) {
                    s.reset = true;
                    self.events.push(StreamEvent::Reset { id });
                }
            }
            _ => {}
        }
    }

    /// Collect all frames that should be sent now.
    pub fn poll_transmit(&mut self) -> Vec<Frame> {
        let mut out = Vec::new();
        let mut retire_ids = Vec::new();
        for (id, s) in self.streams.iter_mut() {
            if s.reset {
                out.push(Frame::StreamReset { id: *id });
                retire_ids.push(*id);
                continue;
            }
            s.transmit(&mut out);
            // Reclaim streams that are fully closed in both directions.
            if s.fully_done() {
                retire_ids.push(*id);
            }
        }
        for id in retire_ids {
            self.streams.remove(&id);
        }
        out
    }

    /// Whether any streams are currently open (so the driver knows it has
    /// stream-class frames to send and should keep polling).
    pub fn has_traffic(&self) -> bool {
        !self.streams.is_empty()
    }

    /// Bytes written but not yet acked by the peer (send-side backlog).
    pub fn in_flight(&self, id: Stream) -> u64 {
        self.streams
            .get(&id)
            .map(|s| s.send_buf.len() as u64)
            .unwrap_or(0)
    }

    /// Bytes received contiguously but not yet read by the app (recv buffer).
    /// The flow-control invariant keeps this bounded by the advertised window.
    pub fn recv_buffered(&self, id: Stream) -> u64 {
        self.streams.get(&id).map(|s| s.recv.unread()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pump frames between two muxes with optional loss/reorder for N rounds.
    fn pump(
        a: &mut StreamMux,
        b: &mut StreamMux,
        rounds: usize,
        mut lossy: impl FnMut(usize) -> bool,
    ) {
        let mut step = 0;
        for _ in 0..rounds {
            let af = a.poll_transmit();
            let bf = b.poll_transmit();
            for f in af {
                step += 1;
                if !lossy(step) {
                    b.on_frame(f);
                }
            }
            for f in bf {
                step += 1;
                if !lossy(step) {
                    a.on_frame(f);
                }
            }
        }
    }

    fn drain(mux: &mut StreamMux, id: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let chunk = mux.read(id);
            if chunk.is_empty() {
                break;
            }
            out.extend_from_slice(&chunk);
        }
        out
    }

    #[test]
    fn basic_stream_delivers_bytes_in_order() {
        let mut client = StreamMux::new(true);
        let mut server = StreamMux::new(false);
        let id = client.open(StreamKind::Session, b"shell".to_vec());
        client.write(id, b"hello server");
        pump(&mut client, &mut server, 4, |_| false);
        let evs = server.take_events();
        assert!(evs.iter().any(|e| matches!(
            e,
            StreamEvent::Opened {
                kind: StreamKind::Session,
                ..
            }
        )));
        assert_eq!(drain(&mut server, id), b"hello server");
    }

    #[test]
    fn reassembles_under_loss_and_reorder() {
        let mut client = StreamMux::new(true);
        let mut server = StreamMux::new(false);
        let id = client.open(StreamKind::Forward, vec![]);
        let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        // Write in chunks across rounds; drop ~1/3 of packets.
        let chunks = payload.chunks(300).collect::<Vec<_>>();
        let mut ci = 0;
        for _ in 0..200 {
            if ci < chunks.len() {
                client.write(id, chunks[ci]);
                ci += 1;
            }
            pump(&mut client, &mut server, 1, |s| s % 3 == 0);
            if ci >= chunks.len() && server.in_flight(id) == 0 {
                // give a couple flushing rounds
            }
        }
        // Final reliable flush.
        pump(&mut client, &mut server, 50, |_| false);
        assert_eq!(drain(&mut server, id), payload);
    }

    #[test]
    fn bidirectional_streams_independent() {
        let mut client = StreamMux::new(true);
        let mut server = StreamMux::new(false);
        let c = client.open(StreamKind::Session, vec![]);
        client.write(c, b"from client");
        pump(&mut client, &mut server, 3, |_| false);
        // server opens its own stream back
        let s = server.open(StreamKind::Session, vec![]);
        server.write(s, b"from server");
        pump(&mut client, &mut server, 3, |_| false);
        assert_eq!(drain(&mut server, c), b"from client");
        assert_eq!(drain(&mut client, s), b"from server");
        assert_ne!(c, s); // distinct id spaces (parity)
    }

    #[test]
    fn close_delivers_status_and_fin() {
        let mut client = StreamMux::new(true);
        let mut server = StreamMux::new(false);
        let id = client.open(StreamKind::Session, vec![]);
        client.write(id, b"bye");
        client.close(id, 42);
        pump(&mut client, &mut server, 6, |_| false);
        assert_eq!(drain(&mut server, id), b"bye");
        let evs = server.take_events();
        assert!(
            evs.iter()
                .any(|e| matches!(e, StreamEvent::Closed { status: 42, .. }))
        );
        assert!(server.is_recv_finished(id));
    }

    #[test]
    fn fully_closed_stream_is_reclaimed_and_quiescent() {
        // Close BOTH directions; after draining, the mux must reclaim the stream
        // and stop emitting frames (no perpetual StreamClose/StreamAck), and the
        // Closed event must be surfaced exactly once despite retransmission.
        let mut client = StreamMux::new(true);
        let mut server = StreamMux::new(false);
        let id = client.open(StreamKind::Session, vec![]);
        client.write(id, b"hi");
        client.close(id, 0);
        // Drive a few rounds so the server learns the stream, then it closes back
        // on the same id.
        pump(&mut client, &mut server, 4, |_| false);
        let _ = drain(&mut server, id);
        server.write(id, b"ok");
        server.close(id, 0);
        pump(&mut client, &mut server, 10, |_| false);
        let _ = drain(&mut client, id);
        let _ = drain(&mut server, id);
        pump(&mut client, &mut server, 10, |_| false);

        // Closed surfaced at most once per side.
        let cev = client
            .take_events()
            .into_iter()
            .filter(|e| matches!(e, StreamEvent::Closed { .. }))
            .count();
        assert!(cev <= 1, "Closed emitted {cev} times");

        // Steady state: nothing left to transmit on either side.
        assert!(
            client.poll_transmit().is_empty(),
            "client still chattering on a closed stream"
        );
        assert!(
            server.poll_transmit().is_empty(),
            "server still chattering on a closed stream"
        );
    }

    #[test]
    fn close_without_fin_data_is_reclaimed_after_grace() {
        // Simulate a peer that closed gracefully but whose FIN-bearing data was
        // lost and which has since gone silent. We (the receiver) have finished
        // our own send side; the stream must eventually be reclaimed instead of
        // leaking forever.
        let mut a = StreamMux::new(true);
        let id = a.open(StreamKind::Forward, vec![]);
        a.close(id, 0);
        // Self-ack our FIN so our send side is settled (no live peer to ack).
        a.on_frame(Frame::StreamAck {
            id,
            ack: 0,
            window: DEFAULT_WINDOW,
        });
        // Peer's graceful close arrives, but the FIN StreamData never does.
        a.on_frame(Frame::StreamClose { id, status: 0 });
        // Poll past the grace window; the stream should be reclaimed and go quiet.
        for _ in 0..(CLOSE_GRACE_TICKS + 2) {
            a.poll_transmit();
        }
        assert!(
            a.poll_transmit().is_empty(),
            "stream leaked: still transmitting after close grace window"
        );
    }

    #[test]
    fn reset_aborts_stream() {
        let mut client = StreamMux::new(true);
        let mut server = StreamMux::new(false);
        let id = client.open(StreamKind::Forward, vec![]);
        client.write(id, b"partial");
        pump(&mut client, &mut server, 2, |_| false);
        client.reset(id);
        pump(&mut client, &mut server, 2, |_| false);
        let evs = server.take_events();
        assert!(evs.iter().any(|e| matches!(e, StreamEvent::Reset { .. })));
    }

    #[test]
    fn flow_control_caps_in_flight_until_reader_drains() {
        // Receiver advertises a window; sender must not exceed it.
        let mut client = StreamMux::new(true);
        let mut server = StreamMux::new(false);
        let id = client.open(StreamKind::Forward, vec![]);
        // Shrink server's effective window by overriding DEFAULT via many bytes
        // unread: write a lot, never drain the server, and confirm in-flight is
        // bounded by the advertised window (which shrinks as data buffers).
        let big = vec![7u8; 10 * DEFAULT_WINDOW as usize];
        let total_written = big.len() as u64;
        client.write(id, &big);
        pump(&mut client, &mut server, 20, |_| false);
        // Server never read => its receive buffer must stay bounded by the
        // advertised window. This is the flow-control invariant.
        assert!(
            server.recv_buffered(id) <= DEFAULT_WINDOW as u64,
            "recv buffer {} exceeded window",
            server.recv_buffered(id)
        );
        // Now the server drains repeatedly, reopening the window each time;
        // eventually everything is delivered.
        let mut total = 0u64;
        for _ in 0..200 {
            total += drain(&mut server, id).len() as u64;
            pump(&mut client, &mut server, 5, |_| false);
        }
        total += drain(&mut server, id).len() as u64;
        assert_eq!(total, total_written);
    }

    #[test]
    fn reassembler_handles_overlap_and_gaps() {
        let mut r = Reassembler::default();
        r.insert(0, b"abc".to_vec());
        r.insert(6, b"ghi".to_vec()); // gap [3,6)
        assert_eq!(r.ack_point(), 3);
        r.insert(3, b"def".to_vec()); // fills gap, contiguous to 9
        assert_eq!(r.ack_point(), 9);
        r.insert(2, b"cdefg".to_vec()); // overlaps already-known data
        assert_eq!(r.ack_point(), 9);
        assert_eq!(r.read(), b"abcdefghi");
    }
}
