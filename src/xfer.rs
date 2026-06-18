//! File I/O helpers for the file-transfer subsystem. The wire request lives in
//! `proto::xfer`; these wrap the local file ends. Integrity is provided by the
//! reliable, authenticated stream the bytes ride on.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

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
