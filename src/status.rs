#![forbid(unsafe_code)]
//! Connection-status overlay and the local detach/escape key.
//!
//! Two small, pure pieces of UX logic, kept here so they can be unit-tested
//! without a live terminal or network:
//!
//! - [`status_banner`] decides whether to show a Mosh-style "last contact N s
//!   ago" banner and what it should say, from the time since the last
//!   authenticated packet.
//! - [`stamp_status`] paints that banner onto the top row of a [`Grid`] (the
//!   diff renderer repaints the real content when it's removed).
//! - [`process_input`] is the escape-key state machine: it intercepts the
//!   detach prefix (`Ctrl-^`) and its follow-up command from the local input
//!   stream, forwarding everything else to the remote shell unchanged.

use std::time::Duration;

use term::Grid;
use term::cell::{Cell, Color, flags};

/// The local escape/detach prefix: `Ctrl-^` (Ctrl-Shift-6, byte 0x1e). Chosen
/// to match Mosh and because it's virtually never sent by normal terminal use.
pub const ESCAPE_KEY: u8 = 0x1e;

/// How long the link must be silent before the status banner appears. Set above
/// the idle keepalive interval (3 s) plus round-trip margin so a healthy idle
/// session, which only hears from the server once per keepalive, never flashes
/// the banner — it appears only on genuine link loss.
pub const SHOW_AFTER: Duration = Duration::from_secs(4);

/// Build the status-banner text, or `None` if the link is healthy enough that
/// nothing should be shown. `since` is the time since the last authenticated
/// packet from the server.
pub fn status_banner(since: Duration) -> Option<String> {
    if since < SHOW_AFTER {
        return None;
    }
    let secs = since.as_secs();
    Some(format!(
        "[noissh] last contact {secs}s ago — reconnecting…  (Ctrl-^ . to quit)"
    ))
}

/// Stamp a one-line status banner onto the top row of `grid`, right-aligned and
/// in reverse video so it stands out over whatever is on screen. This overwrites
/// the underlying cells in `grid` (a throwaway per-frame copy is expected); when
/// the banner stops being stamped, the incremental renderer naturally repaints
/// the real row-0 content.
pub fn stamp_status(grid: &mut Grid, text: &str) {
    if grid.rows == 0 || grid.cols == 0 {
        return;
    }
    let cols = grid.cols;
    // Truncate to the screen width (keeping the leftmost characters).
    let chars: Vec<char> = text.chars().take(cols).collect();
    // Right-align so it sits in the corner like Mosh's notification.
    let start_col = cols - chars.len();
    for (i, &ch) in chars.iter().enumerate() {
        let idx = start_col + i; // row 0: index == column
        grid.cells[idx] = Cell {
            ch,
            fg: Color::Default,
            bg: Color::Default,
            flags: flags::REVERSE | flags::BOLD,
        };
    }
}

/// What [`process_input`] decided to do with a batch of local input bytes.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct InputOutcome {
    /// Bytes to forward to the remote shell (the escape sequences removed).
    pub forward: Vec<u8>,
    /// The user asked to detach/quit (`Ctrl-^` then `.` or `q`).
    pub quit: bool,
}

/// Filter a batch of locally-typed bytes through the escape-key state machine,
/// stripping the detach prefix and its command while forwarding everything else.
///
/// `pending` carries the "saw the prefix, waiting for a command" state across
/// calls, because the prefix and its follow-up key can arrive in separate reads.
///
/// Recognized commands after `Ctrl-^`:
/// - `.` or `q` → quit (sets [`InputOutcome::quit`]).
/// - `Ctrl-^` again → send one literal `Ctrl-^` to the remote.
/// - anything else → the escape is abandoned and the key is ignored.
pub fn process_input(pending: &mut bool, input: &[u8]) -> InputOutcome {
    let mut out = InputOutcome::default();
    for &b in input {
        if *pending {
            *pending = false;
            match b {
                b'.' | b'q' => out.quit = true,
                ESCAPE_KEY => out.forward.push(ESCAPE_KEY), // literal Ctrl-^
                _ => {} // unknown command: abandon the escape, drop the key
            }
        } else if b == ESCAPE_KEY {
            *pending = true;
        } else {
            out.forward.push(b);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use term::Terminal;

    #[test]
    fn banner_hidden_while_link_is_fresh() {
        assert_eq!(status_banner(Duration::from_millis(0)), None);
        assert_eq!(status_banner(SHOW_AFTER - Duration::from_millis(1)), None);
    }

    #[test]
    fn banner_appears_after_threshold_and_counts_seconds() {
        let b = status_banner(SHOW_AFTER + Duration::from_secs(1)).expect("should show");
        let secs = (SHOW_AFTER + Duration::from_secs(1)).as_secs();
        assert!(b.contains(&format!("last contact {secs}s ago")), "{b}");
        assert!(b.contains("Ctrl-^"), "{b}");
    }

    #[test]
    fn stamp_writes_banner_into_top_row_right_aligned() {
        let mut g = Grid::new(3, 40);
        stamp_status(&mut g, "HELLO");
        // Right-aligned: last 5 columns of row 0 carry the text.
        let row0 = g.row_text(0);
        assert!(row0.ends_with("HELLO"), "row0={row0:?}");
        // Reverse-video flag set on stamped cells.
        assert!(g.cell(0, 39).flags & flags::REVERSE != 0);
        // Untouched rows stay blank.
        assert_eq!(g.row_text(1), "");
    }

    #[test]
    fn stamp_truncates_when_wider_than_screen() {
        let mut g = Grid::new(1, 4);
        stamp_status(&mut g, "ABCDEFGH");
        assert_eq!(g.row_text(0), "ABCD");
    }

    #[test]
    fn plain_input_is_forwarded_unchanged() {
        let mut pending = false;
        let out = process_input(&mut pending, b"ls -la\n");
        assert_eq!(out.forward, b"ls -la\n");
        assert!(!out.quit);
        assert!(!pending);
    }

    #[test]
    fn escape_then_dot_quits() {
        let mut pending = false;
        let out = process_input(&mut pending, &[ESCAPE_KEY, b'.']);
        assert!(out.quit);
        assert!(out.forward.is_empty());
    }

    #[test]
    fn escape_split_across_reads_still_quits() {
        let mut pending = false;
        let a = process_input(&mut pending, &[ESCAPE_KEY]);
        assert!(!a.quit && a.forward.is_empty() && pending);
        let b = process_input(&mut pending, b"q");
        assert!(b.quit);
    }

    #[test]
    fn double_escape_sends_one_literal() {
        let mut pending = false;
        let out = process_input(&mut pending, &[ESCAPE_KEY, ESCAPE_KEY]);
        assert_eq!(out.forward, vec![ESCAPE_KEY]);
        assert!(!out.quit);
    }

    #[test]
    fn escape_then_unknown_is_dropped_without_quitting() {
        let mut pending = false;
        let out = process_input(&mut pending, &[ESCAPE_KEY, b'x', b'y']);
        // 'x' abandons the escape; 'y' is ordinary and forwarded.
        assert_eq!(out.forward, b"y");
        assert!(!out.quit);
    }

    #[test]
    fn banner_round_trips_through_a_real_grid_clone() {
        // A realistic grid (as produced by the emulator) can be stamped.
        let mut t = Terminal::new(5, 30);
        t.advance(b"$ echo hi");
        let mut g = t.screen().clone();
        stamp_status(&mut g, "[noissh] reconnecting");
        assert!(g.row_text(0).contains("reconnecting"));
    }
}
