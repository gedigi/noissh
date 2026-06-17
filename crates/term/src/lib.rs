//! Terminal model for noissh.
//!
//! A clean-room, server-side authoritative terminal emulator plus a latest-wins
//! screen-state diff encoder/decoder. No GPL mosh code. Pure model: no I/O.

pub mod cell;
pub mod diff;
pub mod grid;

pub use cell::{flags, Cell, Color};
pub use diff::{apply_diff, encode_diff, is_full, DiffError};
pub use grid::{Grid, Terminal};
