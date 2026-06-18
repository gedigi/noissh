//! File I/O helpers for the file-transfer subsystem. The wire request lives in
//! `proto::xfer`; these wrap the local file ends. Integrity is provided by the
//! reliable, authenticated stream the bytes ride on.

use std::fs::File;
use std::io::{Read, Write};

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
pub struct FileSink {
    file: File,
}

impl FileSink {
    pub fn create(path: &str) -> std::io::Result<Self> {
        Ok(FileSink {
            file: File::create(path)?,
        })
    }

    pub fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.file.write_all(data)
    }
}
