#![forbid(unsafe_code)]
//! Client-side predictive echo engine.
//!
//! On each keystroke the client guesses the visible effect (echo of printable
//! characters, cursor motion), paints the guess immediately and distinctly
//! (the [`term::flags::PREDICTED`] flag, rendered e.g. underlined), and
//! reconciles or abandons predictions as authoritative screen diffs arrive.
//!
//! Clean-room reimplementation of mosh's idea, not its code.

use term::cell::flags;
use term::{Cell, Color, Grid};

/// When predictions are shown to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayMode {
    /// Always paint predictions (useful for tests/aggressive links).
    Always,
    /// Never paint predictions (pure pass-through).
    Never,
    /// Paint predictions only once the server has confirmed at least one,
    /// proving the remote end is echoing — and suspend on a misprediction.
    /// This naturally hides typing at non-echoing prompts (passwords).
    Adaptive,
}

#[derive(Debug, Clone)]
struct Prediction {
    row: usize,
    col: usize,
    ch: char,
}

/// The predictive-echo engine. Holds the latest authoritative screen and the
/// outstanding local predictions layered on top of it.
pub struct Predictor {
    base: Grid,
    preds: Vec<Prediction>,
    cursor: (usize, usize),
    mode: DisplayMode,
    confirmed_echo: bool,
    glitch: bool,
}

impl Predictor {
    /// Create a predictor anchored to an authoritative screen.
    pub fn new(base: Grid) -> Self {
        let cursor = (base.cursor_row, base.cursor_col);
        Predictor {
            base,
            preds: Vec::new(),
            cursor,
            mode: DisplayMode::Adaptive,
            confirmed_echo: false,
            glitch: false,
        }
    }

    pub fn with_mode(mut self, mode: DisplayMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn set_mode(&mut self, mode: DisplayMode) {
        self.mode = mode;
    }

    /// Number of outstanding predictions (for tests/diagnostics).
    pub fn outstanding(&self) -> usize {
        self.preds.len()
    }

    /// Whether predictions are currently being shown.
    pub fn displaying(&self) -> bool {
        match self.mode {
            DisplayMode::Always => true,
            DisplayMode::Never => false,
            DisplayMode::Adaptive => self.confirmed_echo && !self.glitch,
        }
    }

    /// Advance the predicted cursor one cell; returns false if it is already at
    /// the last cell of the last row and cannot advance.
    fn advance_cursor(&mut self) -> bool {
        let (r, c) = self.cursor;
        if c + 1 < self.base.cols {
            self.cursor = (r, c + 1);
            true
        } else if r + 1 < self.base.rows {
            self.cursor = (r + 1, 0);
            true
        } else {
            false
        }
    }

    /// Feed locally-typed bytes, generating predictions for the safe ones.
    pub fn predict_input(&mut self, bytes: &[u8]) {
        for &b in bytes {
            match b {
                0x20..=0x7e => {
                    // Printable ASCII: predict an echo at the cursor — but not
                    // when the screen is full (cursor stuck at the bottom-right
                    // corner), which would stack predictions on one cell.
                    let (row, col) = self.cursor;
                    let at_end = col + 1 >= self.base.cols && row + 1 >= self.base.rows;
                    if !at_end {
                        self.preds.push(Prediction {
                            row,
                            col,
                            ch: b as char,
                        });
                        self.advance_cursor();
                    }
                }
                b'\r' | b'\n' => {
                    // Enter: hard to predict the resulting layout; abandon and
                    // wait for authoritative truth.
                    self.preds.clear();
                    self.cursor = (self.base.cursor_row, self.base.cursor_col);
                }
                0x08 | 0x7f => {
                    // Backspace/DEL: undo the last prediction if any.
                    if self.preds.pop().is_some() {
                        let (r, c) = self.cursor;
                        if c > 0 {
                            self.cursor = (r, c - 1);
                        } else if r > 0 {
                            self.cursor = (r - 1, self.base.cols - 1);
                        }
                    }
                }
                _ => {
                    // Control/escape input (arrows, ctrl-keys): unsafe to predict.
                    self.preds.clear();
                    self.cursor = (self.base.cursor_row, self.base.cursor_col);
                }
            }
        }
    }

    /// Render the authoritative screen with predictions painted on top.
    pub fn overlay(&self) -> Grid {
        let mut g = self.base.clone();
        if !self.displaying() {
            return g;
        }
        for p in &self.preds {
            if p.row < g.rows && p.col < g.cols {
                let i = p.row * g.cols + p.col;
                g.cells[i] = Cell {
                    ch: p.ch,
                    fg: Color::Default,
                    bg: Color::Default,
                    flags: flags::PREDICTED | flags::UNDERLINE,
                };
            }
        }
        g.cursor_row = self.cursor.0.min(g.rows - 1);
        g.cursor_col = self.cursor.1.min(g.cols - 1);
        g
    }

    /// Adopt a fresh authoritative screen, confirming/abandoning predictions.
    pub fn reconcile(&mut self, new_base: Grid) {
        let mut abandoned = false;
        let mut confirmed_any = false;
        let mut kept = Vec::new();
        for p in std::mem::take(&mut self.preds) {
            let reached = new_base.cursor_row > p.row
                || (new_base.cursor_row == p.row && new_base.cursor_col > p.col);
            if reached {
                if new_base.cell(p.row, p.col).ch == p.ch {
                    confirmed_any = true; // server echoed exactly what we guessed
                } else {
                    abandoned = true; // misprediction
                }
            } else {
                kept.push(p);
            }
        }
        if abandoned {
            kept.clear();
            self.glitch = true;
        } else if confirmed_any {
            self.confirmed_echo = true;
            self.glitch = false;
        }
        self.base = new_base;
        // Drop predictions that fall outside the (possibly resized) grid so they
        // cannot accumulate forever, and keep the cursor in bounds.
        kept.retain(|p| p.row < self.base.rows && p.col < self.base.cols);
        self.preds = kept;
        if self.preds.is_empty() {
            self.cursor = (self.base.cursor_row, self.base.cursor_col);
        } else {
            self.cursor = (
                self.cursor.0.min(self.base.rows - 1),
                self.cursor.1.min(self.base.cols - 1),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use term::Terminal;

    fn grid(rows: usize, cols: usize, input: &[u8]) -> Grid {
        let mut t = Terminal::new(rows, cols);
        t.advance(input);
        t.grid.clone()
    }

    fn has_predicted(g: &Grid) -> bool {
        g.cells.iter().any(|c| c.flags & flags::PREDICTED != 0)
    }

    #[test]
    fn resize_smaller_drops_out_of_range_predictions() {
        // Cursor pushed near the right edge of a 20-col grid.
        let base = grid(5, 20, &[b' '; 18]);
        let mut p = Predictor::new(base).with_mode(DisplayMode::Always);
        p.predict_input(b"ab"); // predictions at cols 18, 19
        assert_eq!(p.outstanding(), 2);
        // Server resizes to 10 cols without having echoed the input.
        p.reconcile(grid(5, 10, b""));
        // Out-of-range predictions are dropped (no unbounded accumulation), and
        // the overlay stays in bounds without panicking.
        assert_eq!(p.outstanding(), 0);
        let o = p.overlay();
        assert_eq!(o.cols, 10);
        assert!(o.cursor_col < 10);
    }

    #[test]
    fn always_mode_paints_predicted_glyphs() {
        let base = grid(5, 20, b"$ ");
        let mut p = Predictor::new(base).with_mode(DisplayMode::Always);
        p.predict_input(b"ls");
        let o = p.overlay();
        assert_eq!(o.cell(0, 2).ch, 'l');
        assert_eq!(o.cell(0, 3).ch, 's');
        assert_ne!(o.cell(0, 2).flags & flags::PREDICTED, 0);
        assert_eq!(o.cursor_col, 4);
    }

    #[test]
    fn reconcile_confirms_and_clears_predictions() {
        let base = grid(5, 20, b"$ ");
        let mut p = Predictor::new(base).with_mode(DisplayMode::Always);
        p.predict_input(b"ls");
        assert_eq!(p.outstanding(), 2);
        // Server echoes "ls" and advances cursor past it.
        let echoed = grid(5, 20, b"$ ls");
        p.reconcile(echoed.clone());
        assert_eq!(p.outstanding(), 0);
        // No residual prediction artifacts; overlay matches authoritative.
        let o = p.overlay();
        assert!(!has_predicted(&o));
        assert!(o.render_eq(&echoed));
    }

    #[test]
    fn reconcile_mismatch_abandons_all() {
        let base = grid(5, 20, b"$ ");
        let mut p = Predictor::new(base).with_mode(DisplayMode::Always);
        p.predict_input(b"ls");
        // Server shows something different where we predicted (e.g. remapped).
        let truth = grid(5, 20, b"$ XY");
        p.reconcile(truth.clone());
        assert_eq!(p.outstanding(), 0);
        let o = p.overlay();
        assert!(!has_predicted(&o));
        assert!(o.render_eq(&truth));
    }

    #[test]
    fn backspace_removes_last_prediction() {
        let base = grid(5, 20, b"$ ");
        let mut p = Predictor::new(base).with_mode(DisplayMode::Always);
        p.predict_input(b"lsx");
        p.predict_input(b"\x7f"); // backspace
        let o = p.overlay();
        assert_eq!(o.cell(0, 2).ch, 'l');
        assert_eq!(o.cell(0, 3).ch, 's');
        assert_eq!(o.cell(0, 4).ch, ' '); // 'x' removed
        assert_eq!(p.outstanding(), 2);
    }

    #[test]
    fn adaptive_hidden_until_first_confirmation() {
        let base = grid(5, 20, b"$ ");
        let mut p = Predictor::new(base); // Adaptive by default
        p.predict_input(b"l");
        // Not yet confirmed -> nothing displayed.
        assert!(!p.displaying());
        assert!(!has_predicted(&p.overlay()));
        // Server confirms the echo.
        p.reconcile(grid(5, 20, b"$ l"));
        p.predict_input(b"s");
        assert!(p.displaying());
        assert!(has_predicted(&p.overlay()));
    }

    #[test]
    fn password_prompt_never_displays_predictions() {
        // Server prints a prompt but never echoes typed characters (cursor
        // does not advance), so Adaptive never confirms and never displays.
        let base = grid(5, 30, b"Password: ");
        let mut p = Predictor::new(base);
        p.predict_input(b"hunter2");
        // Re-send the same authoritative state (no echo happened).
        p.reconcile(grid(5, 30, b"Password: "));
        assert!(!p.displaying());
        assert!(!has_predicted(&p.overlay()));
    }

    #[test]
    fn adaptive_suspends_after_misprediction() {
        let base = grid(5, 20, b"$ ");
        let mut p = Predictor::new(base);
        p.predict_input(b"l");
        p.reconcile(grid(5, 20, b"$ l")); // confirm -> displaying enabled
        assert!(p.displaying());
        p.predict_input(b"s");
        p.reconcile(grid(5, 20, b"$ lZ")); // mismatch -> glitch
        assert!(!p.displaying());
    }

    #[test]
    fn replay_recorded_diff_stream_reconciles_with_no_residual() {
        // Type a command; replay the server echoing it one character at a time;
        // assert predictions reconcile to the authoritative state with no
        // residual prediction artifacts at any step or at the end.
        let prompt = b"user@host:~$ ";
        let base = grid(6, 40, prompt);
        let mut p = Predictor::new(base).with_mode(DisplayMode::Always);

        let cmd = b"echo hello";
        p.predict_input(cmd);

        // Server echoes progressively.
        let mut acc = prompt.to_vec();
        for &b in cmd {
            acc.push(b);
            let truth = {
                let mut t = Terminal::new(6, 40);
                t.advance(&acc);
                t.grid.clone()
            };
            p.reconcile(truth.clone());
            // Overlay must never show a glyph that contradicts the truth.
            let o = p.overlay();
            for (i, cell) in o.cells.iter().enumerate() {
                if cell.flags & flags::PREDICTED != 0 {
                    // A still-pending prediction must be ahead of the cursor.
                    let row = i / o.cols;
                    let col = i % o.cols;
                    let reached = truth.cursor_row > row
                        || (truth.cursor_row == row && truth.cursor_col > col);
                    assert!(!reached, "stale prediction left on confirmed cell");
                }
            }
        }
        // Fully echoed: no predictions remain, overlay == authoritative.
        let final_truth = {
            let mut t = Terminal::new(6, 40);
            t.advance(&acc);
            t.grid.clone()
        };
        assert_eq!(p.outstanding(), 0);
        assert!(!has_predicted(&p.overlay()));
        assert!(p.overlay().render_eq(&final_truth));
    }
}
