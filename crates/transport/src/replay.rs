//! Sliding-window anti-replay filter over a 64-bit packet nonce space.
//!
//! Noise already gives strictly-increasing nonces per direction, but on a UDP
//! link packets arrive reordered. This filter accepts each nonce at most once
//! and drops anything older than the window or already seen.

/// Width of the replay window in packets.
pub const WINDOW: u64 = 64;

#[derive(Default)]
pub struct WindowFilter {
    /// Highest nonce accepted so far (None until the first packet).
    max: Option<u64>,
    /// Bit `i` (from LSB) marks that nonce `max - i` has been accepted.
    bitmap: u64,
}

impl WindowFilter {
    pub fn new() -> Self {
        WindowFilter::default()
    }

    /// Returns true and records the nonce if it is fresh; false if it is a
    /// replay or too old to verify.
    pub fn check_and_set(&mut self, nonce: u64) -> bool {
        match self.max {
            None => {
                self.max = Some(nonce);
                self.bitmap = 1; // bit 0 == this nonce
                true
            }
            Some(max) if nonce > max => {
                let diff = nonce - max;
                if diff >= WINDOW {
                    self.bitmap = 1;
                } else {
                    self.bitmap = (self.bitmap << diff) | 1;
                }
                self.max = Some(nonce);
                true
            }
            Some(max) => {
                let diff = max - nonce;
                if diff >= WINDOW {
                    return false; // too old
                }
                let bit = 1u64 << diff;
                if self.bitmap & bit != 0 {
                    return false; // already seen
                }
                self.bitmap |= bit;
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_packet_accepted() {
        let mut w = WindowFilter::new();
        assert!(w.check_and_set(0));
    }

    #[test]
    fn strictly_increasing_all_accepted() {
        let mut w = WindowFilter::new();
        for n in 0..1000 {
            assert!(w.check_and_set(n), "nonce {n} should be fresh");
        }
    }

    #[test]
    fn exact_replay_rejected() {
        let mut w = WindowFilter::new();
        assert!(w.check_and_set(5));
        assert!(!w.check_and_set(5));
    }

    #[test]
    fn reordered_within_window_accepted_once() {
        let mut w = WindowFilter::new();
        assert!(w.check_and_set(10));
        // Older but inside window: accept.
        assert!(w.check_and_set(7));
        assert!(w.check_and_set(8));
        // Replays of those rejected.
        assert!(!w.check_and_set(7));
        assert!(!w.check_and_set(8));
        assert!(!w.check_and_set(10));
    }

    #[test]
    fn too_old_rejected() {
        let mut w = WindowFilter::new();
        assert!(w.check_and_set(100));
        // 100 - 36 = 64 away -> outside window.
        assert!(!w.check_and_set(36));
        assert!(!w.check_and_set(0));
        // Just inside the window edge.
        assert!(w.check_and_set(100 - (WINDOW - 1)));
    }

    #[test]
    fn big_jump_resets_window_but_keeps_accepting() {
        let mut w = WindowFilter::new();
        assert!(w.check_and_set(5));
        assert!(w.check_and_set(1000)); // jump > WINDOW
        assert!(!w.check_and_set(5)); // now far too old
        assert!(w.check_and_set(1001));
        assert!(!w.check_and_set(1000)); // replay
    }
}
