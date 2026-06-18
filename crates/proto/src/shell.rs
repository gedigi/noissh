//! The v1 interactive-shell data plane: server-authoritative state-sync plus
//! the reliable client→server input channel, layered on `wire::Frame`s.
//!
//! Direction-specific meaning of [`wire::Frame::Ack`]:
//! - client → server: acknowledges the highest applied screen-state seq.
//! - server → client: acknowledges contiguous input bytes received.
//!
//! Both shells are I/O-free and operate purely on frames, so the resilience
//! harness can drive them through a lossy/reordering/roaming shim.

use std::collections::BTreeMap;

use predict::{DisplayMode, Predictor};
use term::{Grid, Terminal, apply_diff, encode_diff, is_full};
use transport::{InputReceiver, InputSender};
use wire::Frame;

/// Server-side authoritative screen + input receiver.
pub struct ServerShell {
    term: Terminal,
    seq: u64,
    acked_seq: u64,
    history: BTreeMap<u64, Grid>,
    last_sent: Grid,
    input_rx: InputReceiver,
    force_full: bool,
}

impl ServerShell {
    pub fn new(rows: usize, cols: usize) -> Self {
        let blank = Grid::new(rows, cols);
        let mut history = BTreeMap::new();
        history.insert(0, blank.clone());
        ServerShell {
            term: Terminal::new(rows, cols),
            seq: 0,
            acked_seq: 0,
            history,
            last_sent: blank,
            input_rx: InputReceiver::new(),
            force_full: false,
        }
    }

    /// Re-bind this (already-running) shell to a freshly-connected client after
    /// a reattach: forget the previous client's ack/input progress and arrange
    /// to send the current screen as a full snapshot. The live terminal state
    /// (the running shell's screen) is preserved.
    pub fn rebind_to_new_client(&mut self) {
        let (rows, cols) = (self.term.screen().rows, self.term.screen().cols);
        let blank = Grid::new(rows, cols);
        self.acked_seq = 0;
        self.history.clear();
        self.history.insert(0, blank.clone());
        self.last_sent = blank; // forces poll_diff to re-emit the current screen
        self.input_rx = InputReceiver::new(); // the new client's input restarts at 0
        self.force_full = true;
    }

    /// Feed shell/pty output into the authoritative emulator.
    pub fn feed_output(&mut self, bytes: &[u8]) {
        self.term.advance(bytes);
    }

    pub fn resize(&mut self, rows: usize, cols: usize) {
        self.term.resize(rows, cols);
    }

    pub fn screen(&self) -> &Grid {
        self.term.screen()
    }

    /// Client acknowledged screen-state `seq`.
    pub fn on_state_ack(&mut self, seq: u64) {
        if seq > self.acked_seq && self.history.contains_key(&seq) {
            self.acked_seq = seq;
            // Prune history strictly below the acked base.
            self.history.retain(|&k, _| k >= seq);
        }
    }

    /// Ingest a client Input frame: returns the newly-available bytes (to write
    /// to the pty) and the input-ack frame to send back.
    pub fn ingest_input(&mut self, offset: u64, data: &[u8]) -> (Vec<u8>, Frame) {
        let fresh = self.input_rx.ingest(offset, data);
        (
            fresh,
            Frame::Ack {
                seq: self.input_rx.ack(),
            },
        )
    }

    /// Produce a state-diff frame if the client is behind. Idempotent retransmit
    /// of the acked→current delta until the client catches up.
    pub fn poll_diff(&mut self) -> Option<Frame> {
        let current = self.term.screen().clone();
        if !current.render_eq(&self.last_sent) {
            self.seq += 1;
            self.history.insert(self.seq, current.clone());
            self.last_sent = current;
        }
        if self.seq == self.acked_seq {
            return None; // client is fully caught up
        }
        // After a reattach, send one full snapshot so a fresh client (whose
        // grid dimensions and state differ from the old client's) can apply it
        // unconditionally; thereafter fall back to acked→current deltas.
        let (data, base) = if self.force_full {
            self.force_full = false;
            (encode_diff(None, &self.last_sent), 0)
        } else {
            (
                encode_diff(self.history.get(&self.acked_seq), &self.last_sent),
                self.acked_seq,
            )
        };
        Some(Frame::StateDiff {
            seq: self.seq,
            base,
            data,
        })
    }
}

/// Client-side render grid + predictive echo + input sender.
pub struct ClientShell {
    grid: Grid,
    current_seq: u64,
    input_tx: InputSender,
    predictor: Predictor,
}

impl ClientShell {
    pub fn new(rows: usize, cols: usize) -> Self {
        let grid = Grid::new(rows, cols);
        ClientShell {
            grid: grid.clone(),
            current_seq: 0,
            input_tx: InputSender::new(),
            predictor: Predictor::new(grid),
        }
    }

    pub fn with_prediction(mut self, mode: DisplayMode) -> Self {
        self.predictor.set_mode(mode);
        self
    }

    /// Locally type bytes: queue them for reliable send and predict their echo.
    pub fn type_input(&mut self, bytes: &[u8]) {
        self.input_tx.push(bytes);
        self.predictor.predict_input(bytes);
    }

    /// Whether there is unacknowledged input still to (re)transmit.
    pub fn has_pending_input(&self) -> bool {
        self.input_tx.pending().is_some()
    }

    /// Frames to send now: pending input (if any) plus the screen-state ack.
    pub fn poll_frames(&self) -> Vec<Frame> {
        let mut frames = Vec::new();
        if let Some(input) = self.input_tx.pending() {
            frames.push(input);
        }
        frames.push(Frame::Ack {
            seq: self.current_seq,
        });
        frames
    }

    /// Apply a server state-diff. Full snapshots apply unconditionally; deltas
    /// apply only when their base matches our current state and they are newer.
    pub fn apply_state_diff(&mut self, seq: u64, base: u64, data: &[u8]) -> bool {
        // Full snapshots apply unconditionally; deltas only when their base
        // matches our current state and they are strictly newer.
        let applicable = is_full(data) || (base == self.current_seq && seq > self.current_seq);
        let applied = applicable && apply_diff(&mut self.grid, data).is_ok();
        if applied {
            self.current_seq = seq;
            self.predictor.reconcile(self.grid.clone());
        }
        applied
    }

    /// Server acknowledged input bytes up to `seq`.
    pub fn on_input_ack(&mut self, seq: u64) {
        self.input_tx.on_ack(seq);
    }

    pub fn current_seq(&self) -> u64 {
        self.current_seq
    }

    /// The authoritative render grid (no predictions).
    pub fn screen(&self) -> &Grid {
        &self.grid
    }

    /// The grid as the user should see it (predictions painted on top).
    pub fn overlay(&self) -> Grid {
        self.predictor.overlay()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pump_converge(server: &mut ServerShell, client: &mut ClientShell, rounds: usize) {
        for _ in 0..rounds {
            // server -> client
            if let Some(Frame::StateDiff { seq, base, data }) = server.poll_diff() {
                client.apply_state_diff(seq, base, &data);
            }
            // client -> server (state ack)
            for f in client.poll_frames() {
                match f {
                    Frame::Ack { seq } => server.on_state_ack(seq),
                    Frame::Input { offset, data } => {
                        server.ingest_input(offset, &data);
                    }
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn basic_state_sync_converges() {
        let mut server = ServerShell::new(10, 40);
        let mut client = ClientShell::new(10, 40);
        server.feed_output(b"hello world\r\n$ ");
        pump_converge(&mut server, &mut client, 5);
        assert!(client.screen().render_eq(server.screen()));
        assert_eq!(client.screen().row_text(0), "hello world");
    }

    #[test]
    fn state_sync_converges_under_loss_and_reorder() {
        let mut server = ServerShell::new(12, 40);
        let mut client = ClientShell::new(12, 40);
        let chunks: Vec<&[u8]> = vec![
            b"$ ls -la\r\n",
            b"total 42\r\n",
            b"drwxr-xr-x  5 user  staff\r\n",
            b"-rw-r--r--  1 user  staff  file.txt\r\n",
            b"$ ",
        ];
        let mut drop = 0u64;
        for chunk in chunks {
            server.feed_output(chunk);
            // Lossy rounds: drop ~half the packets in each direction.
            for _ in 0..3 {
                drop += 1;
                if drop.is_multiple_of(2)
                    && let Some(Frame::StateDiff { seq, base, data }) = server.poll_diff()
                {
                    client.apply_state_diff(seq, base, &data);
                }
                for f in client.poll_frames() {
                    drop += 1;
                    if drop.is_multiple_of(3) {
                        continue; // lose this ack
                    }
                    if let Frame::Ack { seq } = f {
                        server.on_state_ack(seq);
                    }
                }
            }
        }
        // Reliable flush.
        pump_converge(&mut server, &mut client, 30);
        assert!(client.screen().render_eq(server.screen()));
        assert_eq!(client.screen().row_text(0), "$ ls -la");
    }

    #[test]
    fn input_channel_delivers_keystrokes_under_loss() {
        let mut server = ServerShell::new(10, 40);
        let mut client = ClientShell::new(10, 40);
        client.type_input(b"echo hi\n");
        let mut received = Vec::new();
        let mut drop = 0u64;
        for _ in 0..20 {
            for f in client.poll_frames() {
                if let Frame::Input { offset, data } = f {
                    drop += 1;
                    if drop.is_multiple_of(2) {
                        continue; // simulate loss
                    }
                    let (fresh, ack) = server.ingest_input(offset, &data);
                    received.extend_from_slice(&fresh);
                    if let Frame::Ack { seq } = ack {
                        client.on_input_ack(seq);
                    }
                }
            }
        }
        assert_eq!(received, b"echo hi\n");
    }

    #[test]
    fn resize_propagates_via_full_snapshot() {
        let mut server = ServerShell::new(10, 40);
        let mut client = ClientShell::new(10, 40);
        server.feed_output(b"before");
        pump_converge(&mut server, &mut client, 5);
        // Server resizes; dimension change forces a full snapshot.
        server.resize(20, 80);
        server.feed_output(b"\r\nafter");
        pump_converge(&mut server, &mut client, 5);
        assert_eq!(client.screen().rows, 20);
        assert_eq!(client.screen().cols, 80);
        assert!(client.screen().render_eq(server.screen()));
    }

    #[test]
    fn predictive_overlay_then_reconciles() {
        let mut server = ServerShell::new(10, 40);
        let mut client = ClientShell::new(10, 40).with_prediction(DisplayMode::Always);
        server.feed_output(b"$ ");
        pump_converge(&mut server, &mut client, 5);
        // Type a char locally; prediction should appear immediately.
        client.type_input(b"x");
        let predicted = client.overlay();
        assert_eq!(predicted.cell(0, 2).ch, 'x');
        // Server echoes it; after convergence overlay matches authoritative.
        server.feed_output(b"x");
        // deliver input then state.
        for f in client.poll_frames() {
            if let Frame::Input { offset, data } = f {
                let (_b, ack) = server.ingest_input(offset, &data);
                if let Frame::Ack { seq } = ack {
                    client.on_input_ack(seq);
                }
            }
        }
        pump_converge(&mut server, &mut client, 5);
        assert!(client.screen().render_eq(server.screen()));
        assert_eq!(client.overlay().cell(0, 2).ch, 'x');
    }
}
