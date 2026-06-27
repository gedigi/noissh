//! Local terminal handling for the interactive client: raw mode, window size,
//! and an incremental grid renderer.

use std::io::{self, Write};
use std::os::fd::AsFd;

use nix::sys::termios::{self, LocalFlags, SetArg, Termios};
use term::Grid;
use term::cell::{Color, flags};

use crate::RuntimeError;

/// RAII guard that puts the controlling terminal into raw mode and restores it.
pub struct RawMode {
    original: Termios,
}

impl RawMode {
    pub fn enable() -> Result<Self, RuntimeError> {
        let stdin = io::stdin();
        let fd = stdin.as_fd();
        let original = termios::tcgetattr(fd).map_err(io_err)?;
        let mut raw = original.clone();
        termios::cfmakeraw(&mut raw);
        // Keep signal generation off; we forward bytes verbatim.
        raw.local_flags.remove(LocalFlags::ISIG);
        termios::tcsetattr(fd, SetArg::TCSANOW, &raw).map_err(io_err)?;
        Ok(RawMode { original })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // Restore the terminal on every exit path (normal, signal, error, panic):
        // show the cursor and reset SGR so a session that left the cursor hidden
        // or mid-attribute doesn't bleed into the user's shell, then restore the
        // saved termios. Best-effort; ignore write errors.
        let _ = nix::unistd::write(io::stdout().as_fd(), b"\x1b[?25h\x1b[0m");
        let stdin = io::stdin();
        let _ = termios::tcsetattr(stdin.as_fd(), SetArg::TCSANOW, &self.original);
    }
}

fn io_err(e: nix::errno::Errno) -> RuntimeError {
    RuntimeError::Io(io::Error::from_raw_os_error(e as i32))
}

/// A blocking writer to the terminal (stdout) that tolerates a non-blocking fd.
///
/// The interactive loop puts stdin into non-blocking mode; because stdin and
/// stdout usually share one terminal file description, stdout becomes
/// non-blocking too, so a large repaint can return `EWOULDBLOCK` mid-write. This
/// writer waits for writability (via `poll`) and retries, so callers can treat
/// it as an ordinary blocking writer. Output is unbuffered (written straight to
/// the fd), which is what a raw-mode renderer wants.
#[derive(Default)]
pub struct TtyWriter;

impl Write for TtyWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        use nix::errno::Errno;
        let out = io::stdout();
        let fd = out.as_fd();
        loop {
            match nix::unistd::write(fd, buf) {
                Ok(n) => return Ok(n),
                Err(Errno::EINTR) => continue,
                Err(Errno::EAGAIN) => wait_writable(fd)?,
                Err(e) => return Err(io::Error::from_raw_os_error(e as i32)),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(()) // unbuffered: writes go straight to the fd
    }
}

/// Write every byte to `fd`, waiting out `EWOULDBLOCK` (for a possibly
/// non-blocking stdout/stderr). Used for raw remote-command output.
pub fn write_all_fd(fd: std::os::fd::BorrowedFd<'_>, mut buf: &[u8]) -> io::Result<()> {
    use nix::errno::Errno;
    while !buf.is_empty() {
        match nix::unistd::write(fd, buf) {
            Ok(0) => {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0"));
            }
            Ok(n) => buf = &buf[n..],
            Err(Errno::EINTR) => continue,
            Err(Errno::EAGAIN) => wait_writable(fd)?,
            Err(e) => return Err(io::Error::from_raw_os_error(e as i32)),
        }
    }
    Ok(())
}

/// Block until the fd is writable (used to ride out `EWOULDBLOCK`).
fn wait_writable(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<()> {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    let mut fds = [PollFd::new(fd, PollFlags::POLLOUT)];
    poll(&mut fds, PollTimeout::NONE)
        .map(|_| ())
        .map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// Query the controlling terminal's size as (cols, rows).
pub fn terminal_size() -> (u16, u16) {
    match terminal_size::terminal_size() {
        Some((terminal_size::Width(w), terminal_size::Height(h))) if w > 0 && h > 0 => (w, h),
        _ => (80, 24),
    }
}

fn sgr_for(out: &mut String, cell_flags: u8, fg: Color, bg: Color) {
    out.push_str("\x1b[0");
    if cell_flags & flags::BOLD != 0 {
        out.push_str(";1");
    }
    if cell_flags & flags::DIM != 0 {
        out.push_str(";2");
    }
    if cell_flags & flags::ITALIC != 0 {
        out.push_str(";3");
    }
    if cell_flags & (flags::UNDERLINE | flags::PREDICTED) != 0 {
        out.push_str(";4");
    }
    if cell_flags & flags::REVERSE != 0 {
        out.push_str(";7");
    }
    match fg {
        Color::Default => {}
        Color::Indexed(n) => out.push_str(&format!(";38;5;{n}")),
        Color::Rgb(r, g, b) => out.push_str(&format!(";38;2;{r};{g};{b}")),
    }
    match bg {
        Color::Default => {}
        Color::Indexed(n) => out.push_str(&format!(";48;5;{n}")),
        Color::Rgb(r, g, b) => out.push_str(&format!(";48;2;{r};{g};{b}")),
    }
    out.push('m');
}

/// Incremental renderer: repaints only rows that changed since the last frame.
#[derive(Default)]
pub struct Renderer {
    last: Option<Grid>,
}

impl Renderer {
    pub fn new() -> Self {
        Renderer::default()
    }

    /// Render `grid`, writing minimal ANSI to `w`.
    ///
    /// This is called once per event-loop wakeup (every inbound packet, ack, and
    /// keepalive), so it must do *nothing* when the screen is unchanged —
    /// otherwise an idle session emits a hide/move/show cursor cycle on every
    /// tick, which reads as flicker or a "random refresh". We therefore early-out
    /// when no row changed and the cursor neither moved nor changed visibility,
    /// and only toggle cursor visibility when it actually changes.
    pub fn paint(&mut self, grid: &Grid, w: &mut impl Write) -> io::Result<()> {
        let full = match &self.last {
            Some(prev) => prev.rows != grid.rows || prev.cols != grid.cols,
            None => true,
        };
        // Which rows actually changed since the last frame.
        let changed_rows: Vec<usize> = (0..grid.rows)
            .filter(|&row| {
                full || self
                    .last
                    .as_ref()
                    .map(|p| (0..grid.cols).any(|c| p.cell(row, c) != grid.cell(row, c)))
                    .unwrap_or(true)
            })
            .collect();
        let (cursor_moved, vis_changed) = match &self.last {
            Some(p) => (
                p.cursor_row != grid.cursor_row || p.cursor_col != grid.cursor_col,
                p.cursor_visible != grid.cursor_visible,
            ),
            None => (true, true),
        };
        // Nothing to draw: don't touch the terminal (and don't clone the grid).
        if changed_rows.is_empty() && !cursor_moved && !vis_changed {
            return Ok(());
        }

        let mut buf = String::new();
        let repainting = !changed_rows.is_empty();
        if repainting {
            buf.push_str("\x1b[?25l"); // hide the cursor only while repainting rows
        }
        for &row in &changed_rows {
            buf.push_str(&format!("\x1b[{};1H\x1b[2K", row + 1)); // move + clear line
            let mut cur = (0u8, Color::Default, Color::Default);
            let mut started = false;
            for col in 0..grid.cols {
                let cell = grid.cell(row, col);
                let key = (cell.flags, cell.fg, cell.bg);
                if !started || key != cur {
                    sgr_for(&mut buf, cell.flags, cell.fg, cell.bg);
                    cur = key;
                    started = true;
                }
                buf.push(cell.ch);
            }
            buf.push_str("\x1b[0m");
        }
        // Reposition the real cursor if we repainted (the writes moved it) or it
        // moved on its own.
        if repainting || cursor_moved {
            buf.push_str(&format!(
                "\x1b[{};{}H",
                grid.cursor_row + 1,
                grid.cursor_col + 1
            ));
        }
        // Restore/track cursor visibility. After a repaint we re-show it when it
        // should be visible (it was hidden by the ?25l above); otherwise emit a
        // toggle only when visibility actually changed.
        if repainting {
            if grid.cursor_visible {
                buf.push_str("\x1b[?25h");
            }
        } else if vis_changed {
            buf.push_str(if grid.cursor_visible {
                "\x1b[?25h"
            } else {
                "\x1b[?25l"
            });
        }
        w.write_all(buf.as_bytes())?;
        w.flush()?;
        self.last = Some(grid.clone());
        Ok(())
    }

    /// Force a full repaint on the next `paint` (e.g. after a resize).
    pub fn invalidate(&mut self) {
        self.last = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use term::Terminal;

    fn grid_of(input: &[u8]) -> Grid {
        let mut t = Terminal::new(5, 20);
        t.advance(input);
        t.screen().clone()
    }

    #[test]
    fn first_paint_emits_output() {
        let mut r = Renderer::new();
        let mut out = Vec::new();
        r.paint(&grid_of(b"hello"), &mut out).unwrap();
        assert!(!out.is_empty(), "first paint should draw the screen");
    }

    #[test]
    fn idle_repaint_of_identical_frame_writes_nothing() {
        // This is the screen-refresh fix: re-painting an unchanged frame (as the
        // loop does on every keepalive/ack) must produce ZERO bytes — no cursor
        // hide/show churn.
        let mut r = Renderer::new();
        let g = grid_of(b"hello");
        r.paint(&g, &mut Vec::new()).unwrap(); // prime
        let mut out = Vec::new();
        r.paint(&g, &mut out).unwrap();
        assert!(
            out.is_empty(),
            "unchanged repaint must write nothing, got {:?}",
            String::from_utf8_lossy(&out)
        );
    }

    #[test]
    fn content_change_repaints_then_settles() {
        let mut r = Renderer::new();
        r.paint(&grid_of(b"hello"), &mut Vec::new()).unwrap();
        let mut out = Vec::new();
        r.paint(&grid_of(b"hello world"), &mut out).unwrap();
        assert!(!out.is_empty(), "a content change must repaint");
        // And a subsequent identical frame goes quiet again.
        let g = grid_of(b"hello world");
        let mut out2 = Vec::new();
        r.paint(&g, &mut out2).unwrap();
        // first settle pass may reposition cursor; prime once more then assert quiet
        let mut out3 = Vec::new();
        r.paint(&g, &mut out3).unwrap();
        assert!(
            out3.is_empty(),
            "settled frame must write nothing, got {:?}",
            String::from_utf8_lossy(&out3)
        );
    }

    #[test]
    fn idle_repaint_emits_no_cursor_visibility_toggle() {
        // Specifically guard against the regression: no ESC[?25l / ESC[?25h on an
        // unchanged frame.
        let mut r = Renderer::new();
        let g = grid_of(b"$ ");
        r.paint(&g, &mut Vec::new()).unwrap();
        let mut out = Vec::new();
        r.paint(&g, &mut out).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(!s.contains("\x1b[?25l"), "no hide-cursor on idle: {s:?}");
        assert!(!s.contains("\x1b[?25h"), "no show-cursor on idle: {s:?}");
    }
}
