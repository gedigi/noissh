//! Local terminal handling for the interactive client: raw mode, window size,
//! and an incremental grid renderer.

use std::io::{self, Write};
use std::os::fd::AsFd;

use nix::sys::termios::{self, LocalFlags, SetArg, Termios};
use term::cell::{flags, Color};
use term::Grid;

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
        let stdin = io::stdin();
        let _ = termios::tcsetattr(stdin.as_fd(), SetArg::TCSANOW, &self.original);
    }
}

fn io_err(e: nix::errno::Errno) -> RuntimeError {
    RuntimeError::Io(io::Error::from_raw_os_error(e as i32))
}

/// Query the controlling terminal's size as (cols, rows).
pub fn terminal_size() -> (u16, u16) {
    use std::os::fd::AsRawFd;
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let fd = io::stdout().as_raw_fd();
    let ok = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) };
    if ok == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
        (ws.ws_col, ws.ws_row)
    } else {
        (80, 24)
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
pub struct Renderer {
    last: Option<Grid>,
}

impl Default for Renderer {
    fn default() -> Self {
        Renderer { last: None }
    }
}

impl Renderer {
    pub fn new() -> Self {
        Renderer::default()
    }

    /// Render `grid`, writing minimal ANSI to `w`.
    pub fn paint(&mut self, grid: &Grid, w: &mut impl Write) -> io::Result<()> {
        let full = match &self.last {
            Some(prev) => prev.rows != grid.rows || prev.cols != grid.cols,
            None => true,
        };
        let mut buf = String::new();
        buf.push_str("\x1b[?25l"); // hide cursor while painting
        for row in 0..grid.rows {
            let changed = full
                || self
                    .last
                    .as_ref()
                    .map(|p| (0..grid.cols).any(|c| p.cell(row, c) != grid.cell(row, c)))
                    .unwrap_or(true);
            if !changed {
                continue;
            }
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
        // Position the real cursor and restore visibility.
        buf.push_str(&format!("\x1b[{};{}H", grid.cursor_row + 1, grid.cursor_col + 1));
        if grid.cursor_visible {
            buf.push_str("\x1b[?25h");
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
