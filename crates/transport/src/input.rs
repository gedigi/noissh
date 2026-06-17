//! Reliable client→server input channel.
//!
//! User keystrokes are an append-only byte stream. The client sends the
//! unacknowledged suffix (retransmitting until acked); the server reconstructs
//! the exact contiguous stream regardless of loss, reorder, or duplication —
//! the same idea mosh uses for its user-input state.

use wire::Frame;

/// Client side: buffers typed bytes and produces retransmittable Input frames.
#[derive(Default)]
pub struct InputSender {
    buffer: Vec<u8>,
    acked: u64,
}

impl InputSender {
    pub fn new() -> Self {
        InputSender::default()
    }

    /// Append freshly typed bytes.
    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// The frame to (re)send: everything not yet acknowledged. `None` if all
    /// sent data is acknowledged.
    pub fn pending(&self) -> Option<Frame> {
        let acked = self.acked as usize;
        if acked >= self.buffer.len() {
            return None;
        }
        Some(Frame::Input {
            offset: self.acked,
            data: self.buffer[acked..].to_vec(),
        })
    }

    /// Total bytes the client has queued.
    pub fn total(&self) -> u64 {
        self.buffer.len() as u64
    }

    /// Process a server ack confirming bytes up to `seq` are received.
    pub fn on_ack(&mut self, seq: u64) {
        if seq > self.acked {
            self.acked = seq.min(self.buffer.len() as u64);
        }
    }
}

/// Server side: reconstructs the contiguous input stream and tracks the ack.
#[derive(Default)]
pub struct InputReceiver {
    received: u64,
}

impl InputReceiver {
    pub fn new() -> Self {
        InputReceiver::default()
    }

    /// Ingest an Input frame, returning newly-available contiguous bytes.
    /// Reordered/duplicate frames yield zero new bytes; gaps are ignored
    /// (the missing prefix will be retransmitted by the sender).
    pub fn ingest(&mut self, offset: u64, data: &[u8]) -> Vec<u8> {
        // Bytes in this frame cover [offset, offset+len).
        let end = offset + data.len() as u64;
        if end <= self.received {
            return Vec::new(); // entirely old
        }
        if offset > self.received {
            return Vec::new(); // gap before this frame; cannot accept yet
        }
        let skip = (self.received - offset) as usize;
        let fresh = data[skip..].to_vec();
        self.received = end;
        fresh
    }

    /// The current ack sequence (contiguous bytes received).
    pub fn ack(&self) -> u64 {
        self.received
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input_parts(f: &Frame) -> (u64, Vec<u8>) {
        match f {
            Frame::Input { offset, data } => (*offset, data.clone()),
            _ => panic!("not an input frame"),
        }
    }

    #[test]
    fn nothing_pending_initially() {
        let s = InputSender::new();
        assert!(s.pending().is_none());
    }

    #[test]
    fn pending_carries_unacked_suffix() {
        let mut s = InputSender::new();
        s.push(b"abc");
        let (off, data) = input_parts(&s.pending().unwrap());
        assert_eq!(off, 0);
        assert_eq!(data, b"abc");
        s.on_ack(2);
        let (off, data) = input_parts(&s.pending().unwrap());
        assert_eq!(off, 2);
        assert_eq!(data, b"c");
        s.on_ack(3);
        assert!(s.pending().is_none());
    }

    #[test]
    fn receiver_reconstructs_contiguous_stream() {
        let mut r = InputReceiver::new();
        assert_eq!(r.ingest(0, b"hello"), b"hello");
        assert_eq!(r.ack(), 5);
        assert_eq!(r.ingest(5, b" world"), b" world");
        assert_eq!(r.ack(), 11);
    }

    #[test]
    fn duplicate_frame_yields_nothing() {
        let mut r = InputReceiver::new();
        assert_eq!(r.ingest(0, b"abc"), b"abc");
        assert_eq!(r.ingest(0, b"abc"), b""); // exact dup
        assert_eq!(r.ack(), 3);
    }

    #[test]
    fn overlapping_retransmit_yields_only_new_tail() {
        let mut r = InputReceiver::new();
        assert_eq!(r.ingest(0, b"abc"), b"abc");
        // Sender retransmits from 0 but with more data appended.
        assert_eq!(r.ingest(0, b"abcde"), b"de");
        assert_eq!(r.ack(), 5);
    }

    #[test]
    fn gap_is_held_until_prefix_arrives() {
        let mut r = InputReceiver::new();
        // Frame starting past current position (lost prefix): ignored.
        assert_eq!(r.ingest(3, b"xyz"), b"");
        assert_eq!(r.ack(), 0);
        // Prefix arrives.
        assert_eq!(r.ingest(0, b"abc"), b"abc");
        assert_eq!(r.ack(), 3);
        // Now the retransmitted full suffix delivers the rest.
        assert_eq!(r.ingest(0, b"abcxyz"), b"xyz");
        assert_eq!(r.ack(), 6);
    }

    #[test]
    fn end_to_end_lossy_reordered_reconstructs_exactly() {
        // Simulate a lossy/reordered link with retransmission until acked.
        let mut s = InputSender::new();
        let mut r = InputReceiver::new();
        let script: &[&[u8]] = &[b"the ", b"quick ", b"brown ", b"fox"];
        let expected: Vec<u8> = script.concat();

        let mut delivered = Vec::new();
        let mut drop_toggle = false;
        for chunk in script {
            s.push(chunk);
            // Try a few delivery rounds, dropping every other packet.
            for _ in 0..3 {
                if let Some(Frame::Input { offset, data }) = s.pending() {
                    drop_toggle = !drop_toggle;
                    if drop_toggle {
                        continue; // simulate loss
                    }
                    let fresh = r.ingest(offset, &data);
                    delivered.extend_from_slice(&fresh);
                    s.on_ack(r.ack());
                }
            }
        }
        // Flush any remainder.
        while let Some(Frame::Input { offset, data }) = s.pending() {
            let fresh = r.ingest(offset, &data);
            delivered.extend_from_slice(&fresh);
            s.on_ack(r.ack());
        }
        assert_eq!(delivered, expected);
    }
}
