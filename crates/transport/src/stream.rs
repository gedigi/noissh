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

/// Max payload of a single `StreamData` frame, chosen so the resulting UDP
/// datagram stays within a conservative path MTU (no IP fragmentation).
pub const MAX_STREAM_CHUNK: usize = 1024;

/// Maximum segment size: one `StreamData` chunk's worth of bytes. Used as the
/// unit for the congestion window.
const MSS: u32 = MAX_STREAM_CHUNK as u32;

/// Initial congestion window (~RFC 6928's 10·MSS), in bytes.
const INIT_CWND: u32 = 10 * MSS;

/// Congestion-window ceiling — no point exceeding the receiver's window.
const MAX_CWND: u32 = DEFAULT_WINDOW;

/// Retransmit timeout bounds, expressed in `poll_transmit` rounds (the core has
/// no wall clock; a round is the drivers' active cadence, ~tens of ms). `INIT`
/// applies until the first RTT sample; the live RTO is then derived from the
/// smoothed RTT (Jacobson/Karels) and clamped to `[MIN, MAX]`.
const INIT_RTO: u32 = 8;
const MIN_RTO: u32 = 2;
const MAX_RTO: u32 = 240;

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
    send_high: u64,    // highest offset transmitted at least once
    send_next: u64,    // total bytes written by us
    peer_window: u32,  // flow-control limit advertised by peer
    send_fin: bool,    // app closed our send side
    fin_sent: bool,    // an (empty) FIN has been emitted at least once
    fin_acked: bool,
    close_status: Option<i32>,

    // --- retransmit timer + RTT estimation (ticks = poll_transmit rounds) ---
    /// Tick the RTO countdown started from (oldest unacked data), or None when
    /// nothing is outstanding.
    rto_start: Option<u64>,
    /// Current retransmit timeout in ticks.
    rto: u32,
    /// Smoothed RTT and its variation (0 = no sample yet).
    srtt: u32,
    rttvar: u32,
    /// In-flight RTT probe: (sequence end it covers, tick it was sent). Cleared
    /// on sample or on retransmit (Karn's algorithm).
    timed: Option<(u64, u64)>,

    // --- congestion control ---
    /// Congestion window in bytes (bounds in-flight alongside the peer window).
    cwnd: u32,
    /// Slow-start threshold in bytes.
    ssthresh: u32,

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
            send_high: 0,
            send_next: 0,
            peer_window: DEFAULT_WINDOW,
            send_fin: false,
            fin_sent: false,
            fin_acked: false,
            close_status: None,
            rto_start: None,
            rto: INIT_RTO,
            srtt: 0,
            rttvar: 0,
            timed: None,
            cwnd: INIT_CWND,
            ssthresh: MAX_CWND,
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
        // Our send side must at least have closed.
        if !self.send_fin {
            return false;
        }
        // Primary path: our FIN was acked AND the peer's FIN-bearing StreamData
        // arrived with all data up to the FIN offset delivered and read.
        if self.fin_acked
            && matches!(self.peer_fin, HalfState::Finished(at)
                if self.recv.delivered >= at && self.recv.unread() == 0)
        {
            return true;
        }
        // Fallback: the peer sent a graceful StreamClose (surfaced to the app)
        // but has since gone silent for the grace window — reclaim so a dead peer
        // can't leak the stream forever, even if our FIN or its FIN-bearing data
        // were never acked/delivered. An alive peer would still be chattering.
        self.close_received && self.close_ticks >= CLOSE_GRACE_TICKS
    }

    fn write(&mut self, data: &[u8]) {
        self.send_buf.extend_from_slice(data);
        self.send_next += data.len() as u64;
    }

    fn on_ack(&mut self, ack: u64, window: u32, now: u64) {
        self.peer_window = window;
        if ack > self.send_base {
            let advance = (ack - self.send_base).min(self.send_buf.len() as u64);
            self.send_buf.drain(0..advance as usize);
            self.send_base += advance;
            self.send_high = self.send_high.max(self.send_base);
            // Congestion control: this ack made forward progress.
            self.grow_cwnd(advance);
            // Restart the RTO timer if data is still outstanding, else stop it;
            // and clear any backoff (RFC 6298: a new ack recomputes the RTO).
            self.rto_start = if self.send_base < self.send_high {
                Some(now)
            } else {
                None
            };
            self.recompute_rto();
        }
        // RTT sample (Karn): only if the probed range is now acked and wasn't
        // retransmitted (a retransmit clears `timed`).
        if let Some((seq, sent)) = self.timed
            && ack >= seq
        {
            self.update_rtt(now.saturating_sub(sent).max(1) as u32);
            self.timed = None;
        }
        // The receiver acks up to the data end; once it covers all our bytes,
        // our FIN is acknowledged (there is no extra FIN byte in the sequence).
        // This only holds once the FIN bit has actually gone out on a frame: if
        // `send_fin` is set after all data is already acked, no frame carried the
        // FIN yet, so the peer hasn't seen the close — `transmit` must still emit
        // an explicit empty FIN.
        if self.send_fin && self.fin_sent && ack >= self.send_next {
            self.fin_acked = true;
        }
    }

    /// Fold a new RTT sample (in ticks) into the smoothed estimate and RTO
    /// (Jacobson/Karels).
    fn update_rtt(&mut self, r: u32) {
        if self.srtt == 0 {
            self.srtt = r;
            self.rttvar = r / 2;
        } else {
            let delta = self.srtt.abs_diff(r);
            self.rttvar = (3 * self.rttvar + delta) / 4;
            self.srtt = (7 * self.srtt + r) / 8;
        }
        self.recompute_rto();
    }

    /// Derive the RTO from the smoothed RTT, or the initial value if unsampled.
    fn recompute_rto(&mut self) {
        self.rto = if self.srtt > 0 {
            (self.srtt + (4 * self.rttvar).max(1)).clamp(MIN_RTO, MAX_RTO)
        } else {
            INIT_RTO
        };
    }

    /// Grow the congestion window for `acked` newly-acknowledged bytes: slow
    /// start (≈ +MSS per ack) below ssthresh, congestion avoidance (≈ +MSS per
    /// RTT) above it.
    fn grow_cwnd(&mut self, acked: u64) {
        let inc = if self.cwnd < self.ssthresh {
            (acked as u32).min(MSS)
        } else {
            ((MSS as u64 * MSS as u64) / self.cwnd.max(1) as u64).max(1) as u32
        };
        self.cwnd = self.cwnd.saturating_add(inc).min(MAX_CWND);
    }

    /// React to a retransmit timeout: halve ssthresh, collapse the window to one
    /// MSS (re-enter slow start), back off the RTO, and invalidate the RTT probe.
    fn on_rto(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(2 * MSS);
        self.cwnd = MSS;
        self.rto = (self.rto.saturating_mul(2)).min(MAX_RTO);
        self.timed = None; // Karn: don't sample retransmitted data
    }

    /// Emit `[from, to)` as MTU-sized StreamData chunks, flagging FIN on the
    /// chunk that reaches `send_next` (while our FIN is still unacked).
    fn emit_range(&mut self, out: &mut Vec<Frame>, from: u64, to: u64) {
        let mut off = from;
        while off < to {
            let chunk_end = (off + MAX_STREAM_CHUNK as u64).min(to);
            let lo = (off - self.send_base) as usize;
            let hi = (chunk_end - self.send_base) as usize;
            let fin = self.send_fin && chunk_end == self.send_next && !self.fin_acked;
            if fin {
                self.fin_sent = true;
            }
            out.push(Frame::StreamData {
                id: self.id,
                offset: off,
                data: self.send_buf[lo..hi].to_vec(),
                fin,
            });
            off = chunk_end;
        }
    }

    /// Frames to (re)transmit at tick `now`, respecting flow control and the
    /// congestion window.
    fn transmit(&mut self, now: u64, out: &mut Vec<Frame>) {
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
        // In-flight is bounded by BOTH the peer's flow-control window and our
        // congestion window. New data goes out immediately (up to that bound);
        // unacked data is retransmitted only after the RTO elapses, so we don't
        // resend the whole window every poll. `emit_range` splits into MTU chunks.
        let cap = self.peer_window.min(self.cwnd) as u64;
        let send_end = self.send_next.min(self.send_base + cap);
        let rto_due = |start: Option<u64>, rto: u32| match start {
            Some(t) => now.saturating_sub(t) >= rto as u64,
            None => true,
        };
        if self.send_high < send_end {
            // Never-sent data: send it now and start an RTT probe if none is open.
            let from = self.send_high.max(self.send_base);
            self.emit_range(out, from, send_end);
            if self.timed.is_none() {
                self.timed = Some((send_end, now));
            }
            self.send_high = send_end;
            if self.rto_start.is_none() {
                self.rto_start = Some(now);
            }
        } else if self.send_base < self.send_high {
            // Outstanding unacked data: retransmit once the RTO has elapsed.
            if rto_due(self.rto_start, self.rto) {
                self.emit_range(out, self.send_base, self.send_high);
                self.rto_start = Some(now);
                self.on_rto();
            }
        } else if self.send_fin && !self.fin_acked && self.send_next == self.send_base {
            // Zero-byte stream closed: send an empty FIN promptly, then on RTO.
            if !self.fin_sent || rto_due(self.rto_start, self.rto) {
                out.push(Frame::StreamData {
                    id: self.id,
                    offset: self.send_next,
                    data: Vec::new(),
                    fin: true,
                });
                self.fin_sent = true;
                self.rto_start = Some(now);
            }
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
        // Count down the close grace window once the peer has gracefully closed
        // (StreamClose surfaced) but we're still missing its FIN-bearing data
        // (see `fully_done`). We don't require our own FIN to be acked here: a
        // silent peer would otherwise leak the stream forever.
        if self.close_received && self.send_fin && matches!(self.peer_fin, HalfState::Open) {
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
    /// Monotonic tick counter (incremented per `poll_transmit`); the clock for
    /// RTT estimation and the retransmit timer.
    now: u64,
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
            now: 0,
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
                let now = self.now;
                if let Some(s) = self.streams.get_mut(&id) {
                    s.on_ack(ack, window, now);
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
        self.now += 1; // advance the RTT/RTO clock one tick per poll
        let now = self.now;
        let mut out = Vec::new();
        let mut retire_ids = Vec::new();
        for (id, s) in self.streams.iter_mut() {
            if s.reset {
                out.push(Frame::StreamReset { id: *id });
                retire_ids.push(*id);
                continue;
            }
            s.transmit(now, &mut out);
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
    fn fin_set_after_data_is_acked_still_reaches_peer() {
        // Regression: if the sender closes its half AFTER all data has already
        // been sent and acked, the FIN bit must still be transmitted explicitly.
        // Otherwise the receiver never learns the stream ended (it sees the data
        // but no FIN), and a transfer waiting on end-of-stream hangs forever.
        let mut a = StreamMux::new(true);
        let mut b = StreamMux::new(false);
        let id = a.open(StreamKind::FileTransfer, b"PUT 5 /tmp/x".to_vec());
        a.write(id, b"hello");
        // Round-trip until every data byte is acked (no close yet).
        pump(&mut a, &mut b, 6, |_| false);
        assert_eq!(drain(&mut b, id), b"hello");
        assert!(
            !b.is_recv_finished(id),
            "receiver must not see EOF before the sender closes"
        );
        // Now close the send half — data is already fully acked.
        a.close(id, 0);
        pump(&mut a, &mut b, 6, |_| false);
        assert!(
            b.is_recv_finished(id),
            "receiver never observed the late FIN"
        );
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
    fn unacked_data_is_not_retransmitted_every_poll() {
        // After sending new data once, an un-acked stream must NOT resend it on
        // every poll — only after the retransmit timeout (RETX_TICKS rounds).
        let mut a = StreamMux::new(true);
        let id = a.open(StreamKind::Forward, vec![]);
        a.write(id, b"hello world");

        let count_data = |frames: &[Frame]| {
            frames
                .iter()
                .filter(|f| matches!(f, Frame::StreamData { data, .. } if !data.is_empty()))
                .count()
        };

        // First poll sends the data.
        assert_eq!(count_data(&a.poll_transmit()), 1);
        // The next INIT_RTO-1 polls send NO data (no spurious retransmits).
        let mut retx = 0;
        for _ in 0..(INIT_RTO - 1) {
            retx += count_data(&a.poll_transmit());
        }
        assert_eq!(retx, 0, "data was retransmitted before the RTO elapsed");
        // By a couple of polls past the RTO, a retransmit has occurred.
        let mut after = 0;
        for _ in 0..2 {
            after += count_data(&a.poll_transmit());
        }
        assert!(after >= 1, "data was never retransmitted after the RTO");
    }

    #[test]
    fn congestion_window_limits_initial_burst() {
        // A fresh stream must not dump its whole flow-control window at once: the
        // first burst is bounded by the initial congestion window.
        let mut a = StreamMux::new(true);
        let id = a.open(StreamKind::Forward, vec![]);
        a.write(id, &vec![0u8; 100 * 1024]);
        let frames = a.poll_transmit();
        let sent: usize = frames
            .iter()
            .filter_map(|f| match f {
                Frame::StreamData { data, .. } => Some(data.len()),
                _ => None,
            })
            .sum();
        assert!(
            sent <= INIT_CWND as usize,
            "initial burst {sent} exceeded the initial congestion window"
        );
        assert!(
            sent >= MSS as usize,
            "should have sent at least one segment"
        );
    }

    #[test]
    fn large_transfer_completes_under_loss_with_congestion_control() {
        // 100 KiB through 25%-loss, exercising RTO-driven retransmission, the
        // congestion-window collapse on loss, and slow-start recovery.
        let mut client = StreamMux::new(true);
        let mut server = StreamMux::new(false);
        let id = client.open(StreamKind::Forward, vec![]);
        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        client.write(id, &payload);
        let mut got = Vec::new();
        for _ in 0..6000 {
            pump(&mut client, &mut server, 1, |s| s % 4 == 0);
            got.extend_from_slice(&drain(&mut server, id));
            if got.len() >= payload.len() {
                break;
            }
        }
        pump(&mut client, &mut server, 100, |_| false);
        got.extend_from_slice(&drain(&mut server, id));
        assert_eq!(got.len(), payload.len(), "not all bytes arrived");
        assert_eq!(got, payload, "payload corrupted in transit");
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
