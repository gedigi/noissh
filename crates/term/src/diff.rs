//! Latest-wins screen-state diff encoder/decoder.
//!
//! The server emits diffs of the render-relevant screen state (cells, cursor,
//! visibility). A diff is either a full snapshot (when dimensions change or no
//! base is known) or a delta listing only changed cells. The client applies
//! them to its render grid. Property: `apply(diff(a, b))` renders as `b`.

use thiserror::Error;
use wire::{get_varint, put_varint, WireError};

use crate::cell::{Cell, Color};
use crate::grid::Grid;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DiffError {
    #[error("wire: {0}")]
    Wire(#[from] WireError),
    #[error("unexpected end of diff")]
    Eof,
    #[error("bad diff tag {0}")]
    BadTag(u8),
    #[error("delta dimensions do not match base grid")]
    DimMismatch,
}

const TAG_FULL: u8 = 0;
const TAG_DELTA: u8 = 1;

fn put_color(out: &mut Vec<u8>, c: Color) {
    match c {
        Color::Default => out.push(0),
        Color::Indexed(n) => {
            out.push(1);
            out.push(n);
        }
        Color::Rgb(r, g, b) => {
            out.push(2);
            out.extend_from_slice(&[r, g, b]);
        }
    }
}

fn get_u8(buf: &[u8], pos: &mut usize) -> Result<u8, DiffError> {
    let b = *buf.get(*pos).ok_or(DiffError::Eof)?;
    *pos += 1;
    Ok(b)
}

fn get_color(buf: &[u8], pos: &mut usize) -> Result<Color, DiffError> {
    Ok(match get_u8(buf, pos)? {
        0 => Color::Default,
        1 => Color::Indexed(get_u8(buf, pos)?),
        2 => {
            let r = get_u8(buf, pos)?;
            let g = get_u8(buf, pos)?;
            let b = get_u8(buf, pos)?;
            Color::Rgb(r, g, b)
        }
        other => return Err(DiffError::BadTag(other)),
    })
}

fn put_cell(out: &mut Vec<u8>, cell: &Cell) {
    put_varint(out, cell.ch as u32 as u64);
    put_color(out, cell.fg);
    put_color(out, cell.bg);
    out.push(cell.flags);
}

fn get_cell(buf: &[u8], pos: &mut usize) -> Result<Cell, DiffError> {
    let ch = char::from_u32(get_varint(buf, pos)? as u32).unwrap_or('\u{fffd}');
    let fg = get_color(buf, pos)?;
    let bg = get_color(buf, pos)?;
    let flags = get_u8(buf, pos)?;
    Ok(Cell { ch, fg, bg, flags })
}

fn put_header(out: &mut Vec<u8>, g: &Grid) {
    put_varint(out, g.rows as u64);
    put_varint(out, g.cols as u64);
    put_varint(out, g.cursor_row as u64);
    put_varint(out, g.cursor_col as u64);
    out.push(g.cursor_visible as u8);
}

/// Encode a diff from `base` (if any) to `target`.
pub fn encode_diff(base: Option<&Grid>, target: &Grid) -> Vec<u8> {
    let mut out = Vec::new();
    let same_dims = base.map(|b| b.rows == target.rows && b.cols == target.cols).unwrap_or(false);
    if !same_dims {
        out.push(TAG_FULL);
        put_header(&mut out, target);
        for cell in &target.cells {
            put_cell(&mut out, cell);
        }
        return out;
    }
    let base = base.unwrap();
    out.push(TAG_DELTA);
    put_header(&mut out, target);
    let changes: Vec<usize> = (0..target.cells.len())
        .filter(|&i| target.cells[i] != base.cells[i])
        .collect();
    put_varint(&mut out, changes.len() as u64);
    for i in changes {
        put_varint(&mut out, i as u64);
        put_cell(&mut out, &target.cells[i]);
    }
    out
}

/// Whether an encoded diff is a full snapshot (applicable regardless of base).
pub fn is_full(bytes: &[u8]) -> bool {
    bytes.first() == Some(&TAG_FULL)
}

/// Apply an encoded diff to `grid`, mutating it to the target state.
pub fn apply_diff(grid: &mut Grid, bytes: &[u8]) -> Result<(), DiffError> {
    let mut pos = 0usize;
    let tag = get_u8(bytes, &mut pos)?;
    let rows = get_varint(bytes, &mut pos)? as usize;
    let cols = get_varint(bytes, &mut pos)? as usize;
    let cur_row = get_varint(bytes, &mut pos)? as usize;
    let cur_col = get_varint(bytes, &mut pos)? as usize;
    let visible = get_u8(bytes, &mut pos)? != 0;

    match tag {
        TAG_FULL => {
            if grid.rows != rows || grid.cols != cols {
                *grid = Grid::new(rows, cols);
            }
            for i in 0..rows * cols {
                grid.cells[i] = get_cell(bytes, &mut pos)?;
            }
        }
        TAG_DELTA => {
            if grid.rows != rows || grid.cols != cols {
                return Err(DiffError::DimMismatch);
            }
            let count = get_varint(bytes, &mut pos)? as usize;
            for _ in 0..count {
                let i = get_varint(bytes, &mut pos)? as usize;
                let cell = get_cell(bytes, &mut pos)?;
                if i < grid.cells.len() {
                    grid.cells[i] = cell;
                }
            }
        }
        other => return Err(DiffError::BadTag(other)),
    }
    grid.cursor_row = cur_row.min(rows - 1);
    grid.cursor_col = cur_col.min(cols - 1);
    grid.cursor_visible = visible;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grid::Terminal;

    fn grid_from(rows: usize, cols: usize, input: &[u8]) -> Grid {
        let mut t = Terminal::new(rows, cols);
        t.advance(input);
        t.grid.clone()
    }

    #[test]
    fn full_snapshot_reconstructs_target() {
        let target = grid_from(5, 20, b"hello\r\nworld\x1b[1mBOLD");
        let bytes = encode_diff(None, &target);
        let mut client = Grid::new(1, 1); // wrong dims -> forces full apply
        apply_diff(&mut client, &bytes).unwrap();
        assert!(client.render_eq(&target));
    }

    #[test]
    fn delta_only_encodes_changes_and_is_smaller() {
        let base = grid_from(10, 40, b"line one\r\nline two");
        let target = grid_from(10, 40, b"line one\r\nline two!!!");
        let delta = encode_diff(Some(&base), &target);
        let full = encode_diff(None, &target);
        assert!(delta.len() < full.len(), "delta {} !< full {}", delta.len(), full.len());
        let mut client = base.clone();
        apply_diff(&mut client, &delta).unwrap();
        assert!(client.render_eq(&target));
    }

    #[test]
    fn dim_change_falls_back_to_full() {
        let base = grid_from(5, 10, b"abc");
        let target = grid_from(8, 20, b"xyz");
        let bytes = encode_diff(Some(&base), &target);
        assert_eq!(bytes[0], TAG_FULL);
        let mut client = base.clone();
        apply_diff(&mut client, &bytes).unwrap();
        assert!(client.render_eq(&target));
    }

    #[test]
    fn delta_with_wrong_base_dims_errors() {
        let base = grid_from(5, 10, b"a");
        let target = grid_from(5, 10, b"b");
        let delta = encode_diff(Some(&base), &target);
        let mut client = Grid::new(6, 10);
        assert_eq!(apply_diff(&mut client, &delta), Err(DiffError::DimMismatch));
    }

    #[test]
    fn property_apply_diff_equals_target() {
        // Pseudo-random sessions; apply(diff(a,b)) must render as b.
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut rng = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            state >> 33
        };
        for _ in 0..300 {
            let mut a = Terminal::new(8, 24);
            let mut b = Terminal::new(8, 24);
            // 'a' and 'b' share a common prefix then diverge — realistic deltas.
            let mut common = Vec::new();
            for _ in 0..(rng() % 60) {
                common.push(printable(rng()));
            }
            a.advance(&common);
            b.advance(&common);
            let mut tail = Vec::new();
            for _ in 0..(rng() % 80) {
                tail.push(printable(rng()));
            }
            b.advance(&tail);

            let delta = encode_diff(Some(&a.grid), &b.grid);
            let mut client = a.grid.clone();
            apply_diff(&mut client, &delta).unwrap();
            assert!(client.render_eq(&b.grid), "delta apply mismatch");

            // Full-snapshot path too.
            let full = encode_diff(None, &b.grid);
            let mut fresh = Grid::new(1, 1);
            apply_diff(&mut fresh, &full).unwrap();
            assert!(fresh.render_eq(&b.grid), "full apply mismatch");
        }
    }

    fn printable(r: u64) -> u8 {
        // Mostly printable ASCII plus the occasional CR/LF/escape introducer.
        match r % 16 {
            13 => b'\r',
            14 => b'\n',
            _ => b' ' + (r % 94) as u8,
        }
    }
}
