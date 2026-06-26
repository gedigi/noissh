//! File I/O helpers for the file-transfer subsystem. The wire request lives in
//! `proto::xfer`; these wrap the local file ends. Integrity is provided by the
//! reliable, authenticated stream the bytes ride on.

use std::fs::File;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Reads a local file in chunks to feed into a session stream (the sending end
/// of a `Put` on the client, or a `Get` on the server).
pub struct FileSource {
    file: File,
}

impl FileSource {
    pub fn open(path: &str) -> std::io::Result<Self> {
        Ok(FileSource {
            file: File::open(path)?,
        })
    }

    pub fn size(&self) -> std::io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    /// Read up to `max` bytes. An empty result means end of file.
    pub fn read_chunk(&mut self, max: usize) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0u8; max];
        let n = self.file.read(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}

/// Writes bytes received from a session stream into a local file (the receiving
/// end of a `Put` on the server, or a `Get` on the client).
///
/// Writes go to a sibling temporary file and are atomically renamed over the
/// destination only on [`FileSink::finalize`]. So a transfer that fails or is
/// aborted never truncates or partially overwrites an existing destination — the
/// temp file is removed on drop instead.
pub struct FileSink {
    file: File,
    tmp: PathBuf,
    dest: PathBuf,
    finalized: bool,
}

/// A temp path next to `dest` (same directory, so the rename is atomic and not
/// cross-device).
fn temp_path(dest: &Path) -> PathBuf {
    let mut name = dest
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| ".noissh".into());
    name.push(format!(".noissh-tmp-{}", std::process::id()));
    dest.with_file_name(name)
}

impl FileSink {
    pub fn create(path: &str) -> std::io::Result<Self> {
        let dest = PathBuf::from(path);
        let tmp = temp_path(&dest);
        let file = File::create(&tmp)?;
        Ok(FileSink {
            file,
            tmp,
            dest,
            finalized: false,
        })
    }

    pub fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.file.write_all(data)
    }

    /// Flush and atomically move the temp file into place. Consumes the sink.
    pub fn finalize(mut self) -> std::io::Result<()> {
        self.file.sync_all()?;
        std::fs::rename(&self.tmp, &self.dest)?;
        self.finalized = true;
        Ok(())
    }
}

impl Drop for FileSink {
    fn drop(&mut self) {
        // An unfinalized sink (failed/aborted transfer) leaves the destination
        // untouched; clean up the temp file.
        if !self.finalized {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_bytes_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KB");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
    }

    #[test]
    fn progress_line_with_and_without_total() {
        let s = progress_line(512 * 1024, Some(1024 * 1024));
        assert!(s.contains("50.0%"), "{s}");
        assert!(s.contains("512.0 KB") && s.contains("1.0 MB"), "{s}");
        // Unknown total: no percentage, just the running count.
        let s = progress_line(2048, None);
        assert!(s.contains("2.0 KB transferred"), "{s}");
        // Never exceeds 100% even if done overshoots.
        let s = progress_line(2048, Some(1024));
        assert!(s.contains("100.0%"), "{s}");
    }
}

/// Format a byte count in human-readable units (e.g. `4.5 MB`).
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} {}", UNITS[0])
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// Render a one-line progress string for `done` of `total` bytes (total `None`
/// when the size isn't known, e.g. a download). Pure, so it's unit-testable.
pub fn progress_line(done: u64, total: Option<u64>) -> String {
    match total {
        Some(t) if t > 0 => {
            let pct = ((done as f64 / t as f64) * 100.0).min(100.0);
            format!(
                "{:>5.1}%  {} / {}",
                pct,
                human_bytes(done),
                human_bytes(t)
            )
        }
        _ => format!("{} transferred", human_bytes(done)),
    }
}

/// A throttled, TTY-only transfer progress reporter. Writes a single carriage-
/// return-updated line to stderr; does nothing when stderr is not a terminal, so
/// scripts and pipelines stay clean.
pub struct Progress {
    total: Option<u64>,
    done: u64,
    last_draw: Instant,
    enabled: bool,
    label: String,
}

impl Progress {
    /// Create a reporter for an operation moving `total` bytes (or `None` if
    /// unknown). `label` is a short prefix like `"↑ report.pdf"`.
    pub fn new(label: impl Into<String>, total: Option<u64>) -> Self {
        Progress {
            total,
            done: 0,
            last_draw: Instant::now() - Duration::from_secs(1),
            enabled: std::io::stderr().is_terminal(),
            label: label.into(),
        }
    }

    /// Record `n` more bytes transferred and redraw if enough time has passed.
    pub fn add(&mut self, n: u64) {
        self.done += n;
        if self.enabled && self.last_draw.elapsed() >= Duration::from_millis(100) {
            self.draw();
            self.last_draw = Instant::now();
        }
    }

    fn draw(&self) {
        // \r returns to column 0; trailing spaces clear any shorter prior line.
        eprint!("\r{}  {}        ", self.label, progress_line(self.done, self.total));
        let _ = std::io::stderr().flush();
    }

    /// Finish the progress line (final draw + newline) if it was active.
    pub fn finish(&self) {
        if self.enabled {
            // Force a final 100%/total draw, then move off the line.
            eprint!(
                "\r{}  {}        \n",
                self.label,
                progress_line(self.done, self.total)
            );
            let _ = std::io::stderr().flush();
        }
    }
}
