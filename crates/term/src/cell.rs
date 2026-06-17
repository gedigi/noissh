//! Cell, color, and attribute model for the screen grid.

/// A terminal color.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Color {
    /// The terminal default (separate fg/bg defaults).
    #[default]
    Default,
    /// One of the 256 indexed palette colors.
    Indexed(u8),
    /// A 24-bit truecolor value.
    Rgb(u8, u8, u8),
}

/// Cell attribute flags (bitfield).
pub mod flags {
    pub const BOLD: u8 = 1 << 0;
    pub const UNDERLINE: u8 = 1 << 1;
    pub const REVERSE: u8 = 1 << 2;
    pub const ITALIC: u8 = 1 << 3;
    pub const DIM: u8 = 1 << 4;
    pub const HIDDEN: u8 = 1 << 5;
    pub const STRIKE: u8 = 1 << 6;
    /// Set by the predictive-echo overlay (client-side only) so predicted
    /// glyphs can be painted distinctly.
    pub const PREDICTED: u8 = 1 << 7;
}

/// A single screen cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    pub fg: Color,
    pub bg: Color,
    pub flags: u8,
}

impl Default for Cell {
    fn default() -> Self {
        Cell {
            ch: ' ',
            fg: Color::Default,
            bg: Color::Default,
            flags: 0,
        }
    }
}

impl Cell {
    pub fn blank() -> Self {
        Cell::default()
    }

    pub fn is_blank(&self) -> bool {
        *self == Cell::default()
    }
}
