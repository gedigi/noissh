//! Authoritative screen grid + terminal emulator driven by `vte`.

use vte::{Params, Parser, Perform};

use crate::cell::{Cell, Color, flags};

/// The authoritative screen state: a grid of cells plus cursor and modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grid {
    pub rows: usize,
    pub cols: usize,
    pub cells: Vec<Cell>,
    pub cursor_row: usize,
    pub cursor_col: usize,
    pub cursor_visible: bool,

    // Emulator working state (part of authoritative state, also serialized).
    pen: Cell,
    autowrap: bool,
    wrap_pending: bool,
    scroll_top: usize,
    scroll_bottom: usize,
    saved: Option<(usize, usize, Cell)>,
    alt_screen: bool,
    alt_saved: Option<Vec<Cell>>,
}

impl Grid {
    pub fn new(rows: usize, cols: usize) -> Self {
        let rows = rows.max(1);
        let cols = cols.max(1);
        Grid {
            rows,
            cols,
            cells: vec![Cell::blank(); rows * cols],
            cursor_row: 0,
            cursor_col: 0,
            cursor_visible: true,
            pen: Cell::blank(),
            autowrap: true,
            wrap_pending: false,
            scroll_top: 0,
            scroll_bottom: rows - 1,
            saved: None,
            alt_screen: false,
            alt_saved: None,
        }
    }

    #[inline]
    fn idx(&self, row: usize, col: usize) -> usize {
        row * self.cols + col
    }

    /// Read a cell (row, col). Returns blank for out-of-range.
    pub fn cell(&self, row: usize, col: usize) -> Cell {
        if row < self.rows && col < self.cols {
            self.cells[self.idx(row, col)]
        } else {
            Cell::blank()
        }
    }

    /// Compare only the render-relevant state (cells, cursor, visibility).
    /// State-sync transmits exactly this; the client does not re-emulate the
    /// pen, scroll region, or alt-buffer bookkeeping.
    pub fn render_eq(&self, other: &Grid) -> bool {
        self.rows == other.rows
            && self.cols == other.cols
            && self.cells == other.cells
            && self.cursor_row == other.cursor_row
            && self.cursor_col == other.cursor_col
            && self.cursor_visible == other.cursor_visible
    }

    /// The text content of a row (trailing blanks trimmed) — convenience for tests.
    pub fn row_text(&self, row: usize) -> String {
        if row >= self.rows {
            return String::new();
        }
        let start = self.idx(row, 0);
        let s: String = self.cells[start..start + self.cols]
            .iter()
            .map(|c| c.ch)
            .collect();
        s.trim_end().to_string()
    }

    fn put_char(&mut self, c: char) {
        if self.wrap_pending && self.autowrap {
            self.cursor_col = 0;
            self.line_feed();
            self.wrap_pending = false;
        }
        let (r, col) = (self.cursor_row, self.cursor_col);
        let i = self.idx(r, col);
        let mut cell = self.pen;
        cell.ch = c;
        self.cells[i] = cell;
        if self.cursor_col + 1 < self.cols {
            self.cursor_col += 1;
        } else if self.autowrap {
            self.wrap_pending = true;
        }
    }

    fn line_feed(&mut self) {
        if self.cursor_row == self.scroll_bottom {
            self.scroll_up(1);
        } else if self.cursor_row + 1 < self.rows {
            self.cursor_row += 1;
        }
    }

    fn reverse_index(&mut self) {
        if self.cursor_row == self.scroll_top {
            self.scroll_down(1);
        } else if self.cursor_row > 0 {
            self.cursor_row -= 1;
        }
    }

    fn scroll_up(&mut self, n: usize) {
        let n = n.min(self.scroll_bottom - self.scroll_top + 1);
        for r in self.scroll_top..=self.scroll_bottom {
            if r + n <= self.scroll_bottom {
                let src = self.idx(r + n, 0);
                let dst = self.idx(r, 0);
                self.cells.copy_within(src..src + self.cols, dst);
            } else {
                let start = self.idx(r, 0);
                for c in 0..self.cols {
                    self.cells[start + c] = Cell::blank();
                }
            }
        }
    }

    fn scroll_down(&mut self, n: usize) {
        let n = n.min(self.scroll_bottom - self.scroll_top + 1);
        for r in (self.scroll_top..=self.scroll_bottom).rev() {
            if r >= self.scroll_top + n {
                let src = self.idx(r - n, 0);
                let dst = self.idx(r, 0);
                self.cells.copy_within(src..src + self.cols, dst);
            } else {
                let start = self.idx(r, 0);
                for c in 0..self.cols {
                    self.cells[start + c] = Cell::blank();
                }
            }
        }
    }

    fn move_to(&mut self, row: usize, col: usize) {
        self.cursor_row = row.min(self.rows - 1);
        self.cursor_col = col.min(self.cols - 1);
        self.wrap_pending = false;
    }

    fn erase_in_display(&mut self, mode: u16) {
        match mode {
            0 => {
                // cursor to end of screen
                let from = self.idx(self.cursor_row, self.cursor_col);
                for c in &mut self.cells[from..] {
                    *c = Cell::blank();
                }
            }
            1 => {
                let to = self.idx(self.cursor_row, self.cursor_col);
                for c in &mut self.cells[..=to] {
                    *c = Cell::blank();
                }
            }
            _ => {
                for c in &mut self.cells {
                    *c = Cell::blank();
                }
            }
        }
    }

    fn erase_in_line(&mut self, mode: u16) {
        let row_start = self.idx(self.cursor_row, 0);
        match mode {
            0 => {
                for c in self.cursor_col..self.cols {
                    self.cells[row_start + c] = Cell::blank();
                }
            }
            1 => {
                for c in 0..=self.cursor_col {
                    self.cells[row_start + c] = Cell::blank();
                }
            }
            _ => {
                for c in 0..self.cols {
                    self.cells[row_start + c] = Cell::blank();
                }
            }
        }
    }

    fn insert_blank_chars(&mut self, n: usize) {
        let row_start = self.idx(self.cursor_row, 0);
        let col = self.cursor_col;
        let n = n.min(self.cols - col);
        for c in (col..self.cols).rev() {
            if c >= col + n {
                self.cells[row_start + c] = self.cells[row_start + c - n];
            } else {
                self.cells[row_start + c] = Cell::blank();
            }
        }
    }

    fn delete_chars(&mut self, n: usize) {
        let row_start = self.idx(self.cursor_row, 0);
        let col = self.cursor_col;
        let n = n.min(self.cols - col);
        for c in col..self.cols {
            if c + n < self.cols {
                self.cells[row_start + c] = self.cells[row_start + c + n];
            } else {
                self.cells[row_start + c] = Cell::blank();
            }
        }
    }

    fn insert_lines(&mut self, n: usize) {
        if self.cursor_row < self.scroll_top || self.cursor_row > self.scroll_bottom {
            return;
        }
        let saved_top = self.scroll_top;
        self.scroll_top = self.cursor_row;
        self.scroll_down(n);
        self.scroll_top = saved_top;
    }

    fn delete_lines(&mut self, n: usize) {
        if self.cursor_row < self.scroll_top || self.cursor_row > self.scroll_bottom {
            return;
        }
        let saved_top = self.scroll_top;
        self.scroll_top = self.cursor_row;
        self.scroll_up(n);
        self.scroll_top = saved_top;
    }

    fn enter_alt_screen(&mut self) {
        if !self.alt_screen {
            self.alt_screen = true;
            self.alt_saved = Some(std::mem::replace(
                &mut self.cells,
                vec![Cell::blank(); self.rows * self.cols],
            ));
            self.move_to(0, 0);
        }
    }

    fn leave_alt_screen(&mut self) {
        if self.alt_screen {
            self.alt_screen = false;
            if let Some(main) = self.alt_saved.take() {
                self.cells = main;
            }
        }
    }

    fn set_sgr(&mut self, params: &Params) {
        let groups: Vec<Vec<u16>> = params.iter().map(|s| s.to_vec()).collect();
        if groups.is_empty() {
            self.pen = Cell::blank();
            return;
        }
        let mut i = 0;
        while i < groups.len() {
            let g = &groups[i];
            let code = g.first().copied().unwrap_or(0);
            match code {
                0 => self.pen = Cell::blank(),
                1 => self.pen.flags |= flags::BOLD,
                2 => self.pen.flags |= flags::DIM,
                3 => self.pen.flags |= flags::ITALIC,
                4 => self.pen.flags |= flags::UNDERLINE,
                7 => self.pen.flags |= flags::REVERSE,
                8 => self.pen.flags |= flags::HIDDEN,
                9 => self.pen.flags |= flags::STRIKE,
                22 => self.pen.flags &= !(flags::BOLD | flags::DIM),
                23 => self.pen.flags &= !flags::ITALIC,
                24 => self.pen.flags &= !flags::UNDERLINE,
                27 => self.pen.flags &= !flags::REVERSE,
                28 => self.pen.flags &= !flags::HIDDEN,
                29 => self.pen.flags &= !flags::STRIKE,
                30..=37 => self.pen.fg = Color::Indexed((code - 30) as u8),
                90..=97 => self.pen.fg = Color::Indexed((code - 90 + 8) as u8),
                39 => self.pen.fg = Color::Default,
                40..=47 => self.pen.bg = Color::Indexed((code - 40) as u8),
                100..=107 => self.pen.bg = Color::Indexed((code - 100 + 8) as u8),
                49 => self.pen.bg = Color::Default,
                38 | 48 => {
                    // Extended color: either colon-subparams in this group, or
                    // semicolon params following.
                    let is_fg = code == 38;
                    if g.len() >= 2 {
                        // colon form: 38:5:n or 38:2:r:g:b
                        let color = parse_ext_color(&g[1..]);
                        if let Some(c) = color {
                            if is_fg {
                                self.pen.fg = c
                            } else {
                                self.pen.bg = c
                            }
                        }
                    } else {
                        let kind = groups.get(i + 1).and_then(|x| x.first().copied());
                        match kind {
                            Some(5) => {
                                if let Some(n) = groups.get(i + 2).and_then(|x| x.first().copied())
                                {
                                    let c = Color::Indexed(n as u8);
                                    if is_fg {
                                        self.pen.fg = c
                                    } else {
                                        self.pen.bg = c
                                    }
                                }
                                i += 2;
                            }
                            Some(2) => {
                                let r = groups
                                    .get(i + 2)
                                    .and_then(|x| x.first().copied())
                                    .unwrap_or(0) as u8;
                                let gg = groups
                                    .get(i + 3)
                                    .and_then(|x| x.first().copied())
                                    .unwrap_or(0) as u8;
                                let b = groups
                                    .get(i + 4)
                                    .and_then(|x| x.first().copied())
                                    .unwrap_or(0) as u8;
                                let c = Color::Rgb(r, gg, b);
                                if is_fg {
                                    self.pen.fg = c
                                } else {
                                    self.pen.bg = c
                                }
                                i += 4;
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }

    /// Resize the grid, preserving overlapping content from the top-left.
    pub fn resize(&mut self, rows: usize, cols: usize) {
        let rows = rows.max(1);
        let cols = cols.max(1);
        let mut new = vec![Cell::blank(); rows * cols];
        for r in 0..rows.min(self.rows) {
            for c in 0..cols.min(self.cols) {
                new[r * cols + c] = self.cells[r * self.cols + c];
            }
        }
        // Also resize the saved alt buffer if present.
        if let Some(alt) = &self.alt_saved {
            let mut new_alt = vec![Cell::blank(); rows * cols];
            for r in 0..rows.min(self.rows) {
                for c in 0..cols.min(self.cols) {
                    new_alt[r * cols + c] = alt[r * self.cols + c];
                }
            }
            self.alt_saved = Some(new_alt);
        }
        self.cells = new;
        self.rows = rows;
        self.cols = cols;
        self.scroll_top = 0;
        self.scroll_bottom = rows - 1;
        self.cursor_row = self.cursor_row.min(rows - 1);
        self.cursor_col = self.cursor_col.min(cols - 1);
        self.wrap_pending = false;
    }
}

fn parse_ext_color(sub: &[u16]) -> Option<Color> {
    match sub.first().copied() {
        Some(5) => sub.get(1).map(|n| Color::Indexed(*n as u8)),
        Some(2) => {
            // Could be 2:r:g:b or 2:colorspace:r:g:b. Take the last three.
            if sub.len() >= 4 {
                Some(Color::Rgb(
                    sub[sub.len() - 3] as u8,
                    sub[sub.len() - 2] as u8,
                    sub[sub.len() - 1] as u8,
                ))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extract CSI param at `idx`, substituting `default` for missing/zero.
fn arg(params: &Params, idx: usize, default: u16) -> u16 {
    match params.iter().nth(idx).and_then(|s| s.first().copied()) {
        Some(0) | None => default,
        Some(v) => v,
    }
}

/// Extract CSI param at `idx` allowing zero (for ED/EL/SGR-like modes).
fn arg_raw(params: &Params, idx: usize, default: u16) -> u16 {
    params
        .iter()
        .nth(idx)
        .and_then(|s| s.first().copied())
        .unwrap_or(default)
}

impl Perform for Grid {
    fn print(&mut self, c: char) {
        self.put_char(c);
    }

    fn execute(&mut self, byte: u8) {
        match byte {
            b'\n' | 0x0b | 0x0c => self.line_feed(),
            b'\r' => {
                self.cursor_col = 0;
                self.wrap_pending = false;
            }
            0x08 => {
                if self.cursor_col > 0 {
                    self.cursor_col -= 1;
                }
                self.wrap_pending = false;
            }
            b'\t' => {
                let next = ((self.cursor_col / 8) + 1) * 8;
                self.cursor_col = next.min(self.cols - 1);
            }
            _ => {}
        }
    }

    fn csi_dispatch(&mut self, params: &Params, intermediates: &[u8], _ignore: bool, action: char) {
        let private = intermediates.first() == Some(&b'?');
        match action {
            'A' => {
                let n = arg(params, 0, 1) as usize;
                self.cursor_row = self.cursor_row.saturating_sub(n);
                self.wrap_pending = false;
            }
            'B' => {
                let n = arg(params, 0, 1) as usize;
                self.cursor_row = (self.cursor_row + n).min(self.rows - 1);
                self.wrap_pending = false;
            }
            'C' => {
                let n = arg(params, 0, 1) as usize;
                self.cursor_col = (self.cursor_col + n).min(self.cols - 1);
                self.wrap_pending = false;
            }
            'D' => {
                let n = arg(params, 0, 1) as usize;
                self.cursor_col = self.cursor_col.saturating_sub(n);
                self.wrap_pending = false;
            }
            'G' => {
                let col = arg(params, 0, 1) as usize - 1;
                self.cursor_col = col.min(self.cols - 1);
                self.wrap_pending = false;
            }
            'd' => {
                let row = arg(params, 0, 1) as usize - 1;
                self.cursor_row = row.min(self.rows - 1);
                self.wrap_pending = false;
            }
            'H' | 'f' => {
                let row = arg(params, 0, 1) as usize - 1;
                let col = arg(params, 1, 1) as usize - 1;
                self.move_to(row, col);
            }
            'J' => self.erase_in_display(arg_raw(params, 0, 0)),
            'K' => self.erase_in_line(arg_raw(params, 0, 0)),
            '@' => self.insert_blank_chars(arg(params, 0, 1) as usize),
            'P' => self.delete_chars(arg(params, 0, 1) as usize),
            'L' => self.insert_lines(arg(params, 0, 1) as usize),
            'M' => self.delete_lines(arg(params, 0, 1) as usize),
            'S' => self.scroll_up(arg(params, 0, 1) as usize),
            'T' => self.scroll_down(arg(params, 0, 1) as usize),
            'r' => {
                let top = arg(params, 0, 1) as usize - 1;
                let bottom = arg(params, 1, self.rows as u16) as usize - 1;
                if top < bottom && bottom < self.rows {
                    self.scroll_top = top;
                    self.scroll_bottom = bottom;
                    self.move_to(0, 0);
                }
            }
            'm' => self.set_sgr(params),
            'h' if private => self.set_private_mode(arg_raw(params, 0, 0), true),
            'l' if private => self.set_private_mode(arg_raw(params, 0, 0), false),
            _ => {}
        }
    }

    fn esc_dispatch(&mut self, _intermediates: &[u8], _ignore: bool, byte: u8) {
        match byte {
            b'D' => self.line_feed(),
            b'M' => self.reverse_index(),
            b'E' => {
                self.cursor_col = 0;
                self.line_feed();
            }
            b'7' => self.saved = Some((self.cursor_row, self.cursor_col, self.pen)),
            b'8' => {
                if let Some((r, c, pen)) = self.saved {
                    self.cursor_row = r.min(self.rows - 1);
                    self.cursor_col = c.min(self.cols - 1);
                    self.pen = pen;
                }
            }
            b'c' => {
                let (rows, cols) = (self.rows, self.cols);
                *self = Grid::new(rows, cols);
            }
            _ => {}
        }
    }
}

impl Grid {
    fn set_private_mode(&mut self, mode: u16, enable: bool) {
        match mode {
            7 => self.autowrap = enable,
            25 => self.cursor_visible = enable,
            1049 | 47 | 1047 => {
                if enable {
                    self.enter_alt_screen();
                } else {
                    self.leave_alt_screen();
                }
            }
            _ => {}
        }
    }
}

/// A terminal emulator: a parser feeding an authoritative [`Grid`].
pub struct Terminal {
    parser: Parser,
    pub grid: Grid,
}

impl Terminal {
    pub fn new(rows: usize, cols: usize) -> Self {
        Terminal {
            parser: Parser::new(),
            grid: Grid::new(rows, cols),
        }
    }

    /// Feed output bytes from the shell/pty into the emulator.
    pub fn advance(&mut self, bytes: &[u8]) {
        self.parser.advance(&mut self.grid, bytes);
    }

    pub fn screen(&self) -> &Grid {
        &self.grid
    }

    pub fn resize(&mut self, rows: usize, cols: usize) {
        self.grid.resize(rows, cols);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8]) -> Terminal {
        let mut t = Terminal::new(5, 20);
        t.advance(input);
        t
    }

    #[test]
    fn prints_text() {
        let t = run(b"hello");
        assert_eq!(t.screen().row_text(0), "hello");
        assert_eq!(t.screen().cursor_col, 5);
    }

    #[test]
    fn carriage_return_and_newline() {
        let t = run(b"abc\r\ndef");
        assert_eq!(t.screen().row_text(0), "abc");
        assert_eq!(t.screen().row_text(1), "def");
        assert_eq!(t.screen().cursor_row, 1);
    }

    #[test]
    fn backspace_moves_left() {
        let t = run(b"abc\x08X");
        assert_eq!(t.screen().row_text(0), "abX");
    }

    #[test]
    fn tab_advances_to_stop() {
        let t = run(b"a\tb");
        // 'a' at col 0, tab -> col 8, 'b' at col 8
        assert_eq!(t.screen().cell(0, 8).ch, 'b');
    }

    #[test]
    fn autowrap_wraps_to_next_line() {
        let mut t = Terminal::new(3, 4);
        t.advance(b"abcdef");
        assert_eq!(t.screen().row_text(0), "abcd");
        assert_eq!(t.screen().row_text(1), "ef");
    }

    #[test]
    fn cursor_position_absolute() {
        let t = run(b"\x1b[2;3HX");
        assert_eq!(t.screen().cell(1, 2).ch, 'X');
    }

    #[test]
    fn cursor_movement_relative() {
        let t = run(b"\x1b[3CX"); // forward 3 -> col 3
        assert_eq!(t.screen().cell(0, 3).ch, 'X');
    }

    #[test]
    fn erase_display_clears_all() {
        let t = run(b"hello\x1b[2J");
        assert_eq!(t.screen().row_text(0), "");
    }

    #[test]
    fn erase_line_to_end() {
        let t = run(b"abcdef\r\x1b[3C\x1b[K");
        assert_eq!(t.screen().row_text(0), "abc");
    }

    #[test]
    fn sgr_bold_underline_then_reset() {
        let mut t = Terminal::new(2, 10);
        t.advance(b"\x1b[1;4mAB\x1b[0mC");
        assert_ne!(t.screen().cell(0, 0).flags & flags::BOLD, 0);
        assert_ne!(t.screen().cell(0, 0).flags & flags::UNDERLINE, 0);
        assert_eq!(t.screen().cell(0, 2).flags, 0);
    }

    #[test]
    fn sgr_colors_indexed_and_truecolor() {
        let mut t = Terminal::new(2, 10);
        t.advance(b"\x1b[31mR\x1b[38;5;200mP\x1b[38;2;10;20;30mT");
        assert_eq!(t.screen().cell(0, 0).fg, Color::Indexed(1));
        assert_eq!(t.screen().cell(0, 1).fg, Color::Indexed(200));
        assert_eq!(t.screen().cell(0, 2).fg, Color::Rgb(10, 20, 30));
    }

    #[test]
    fn scroll_region_and_index() {
        // 5 rows; set region 1..3 (1-based 2;4), fill, force scroll.
        let mut t = Terminal::new(5, 5);
        t.advance(b"\x1b[2;4r"); // region rows 1..=3
        t.advance(b"\x1b[2;1Haaa"); // row1
        t.advance(b"\x1b[3;1Hbbb"); // row2
        t.advance(b"\x1b[4;1Hccc"); // row3 (bottom of region)
        t.advance(b"\x1b[4;1H\n"); // line feed at bottom -> scroll region up
        assert_eq!(t.screen().row_text(1), "bbb");
        assert_eq!(t.screen().row_text(2), "ccc");
    }

    #[test]
    fn alt_screen_save_restore() {
        let mut t = Terminal::new(3, 10);
        t.advance(b"main");
        t.advance(b"\x1b[?1049h"); // enter alt
        assert_eq!(t.screen().row_text(0), "");
        t.advance(b"altbuf");
        assert_eq!(t.screen().row_text(0), "altbuf");
        t.advance(b"\x1b[?1049l"); // leave alt -> restore main
        assert_eq!(t.screen().row_text(0), "main");
    }

    #[test]
    fn insert_and_delete_chars() {
        let mut t = Terminal::new(2, 10);
        t.advance(b"abcdef\r\x1b[2P"); // delete 2 chars at col0
        assert_eq!(t.screen().row_text(0), "cdef");
        t.advance(b"\r\x1b[2@"); // insert 2 blanks at col0, shifting "cdef" right
        assert_eq!(t.screen().row_text(0), "  cdef"); // leading blanks kept, trailing trimmed
        assert_eq!(t.screen().cell(0, 0).ch, ' ');
        assert_eq!(t.screen().cell(0, 2).ch, 'c');
    }

    #[test]
    fn utf8_multibyte_chars() {
        let t = run("héllo→".as_bytes());
        assert_eq!(t.screen().cell(0, 1).ch, 'é');
        assert_eq!(t.screen().cell(0, 5).ch, '→');
    }

    #[test]
    fn cursor_visibility_toggle() {
        let mut t = Terminal::new(2, 5);
        t.advance(b"\x1b[?25l");
        assert!(!t.screen().cursor_visible);
        t.advance(b"\x1b[?25h");
        assert!(t.screen().cursor_visible);
    }

    #[test]
    fn resize_preserves_topleft() {
        let mut t = Terminal::new(3, 10);
        t.advance(b"hello");
        t.resize(5, 20);
        assert_eq!(t.screen().row_text(0), "hello");
        assert_eq!(t.screen().rows, 5);
        assert_eq!(t.screen().cols, 20);
    }

    #[test]
    fn fuzz_random_escape_bytes_never_panics() {
        let mut state = 0xDEADBEEFu64;
        for _ in 0..5000 {
            let mut t = Terminal::new(10, 40);
            let mut buf = Vec::new();
            for _ in 0..100 {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                buf.push((state >> 40) as u8);
            }
            t.advance(&buf); // must not panic
        }
    }
}
