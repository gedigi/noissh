//! File-transfer request header carried in a `FileTransfer` stream's open
//! metadata. The byte stream that follows is the file contents (for `Put`) or is
//! sent back by the server (for `Get`). Integrity is guaranteed by the reliable,
//! AEAD-authenticated stream — no separate checksum is required.

/// A file-transfer request, encoded into the stream's open metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XferRequest {
    /// Upload: the client will send `size` bytes to be written at `path`.
    Put { path: String, size: u64 },
    /// Download: the server should send the contents of `path`.
    Get { path: String },
}

impl XferRequest {
    /// Encode as `PUT <size> <path>` / `GET <path>` (path is the remainder, so it
    /// may contain spaces).
    pub fn encode(&self) -> Vec<u8> {
        match self {
            XferRequest::Put { path, size } => format!("PUT {size} {path}").into_bytes(),
            XferRequest::Get { path } => format!("GET {path}").into_bytes(),
        }
    }

    pub fn parse(meta: &[u8]) -> Option<XferRequest> {
        let s = std::str::from_utf8(meta).ok()?;
        if let Some(rest) = s.strip_prefix("PUT ") {
            let (size, path) = rest.split_once(' ')?;
            let size: u64 = size.parse().ok()?;
            if path.is_empty() {
                return None;
            }
            Some(XferRequest::Put {
                path: path.to_string(),
                size,
            })
        } else if let Some(path) = s.strip_prefix("GET ") {
            if path.is_empty() {
                return None;
            }
            Some(XferRequest::Get {
                path: path.to_string(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_roundtrip() {
        let r = XferRequest::Put {
            path: "/tmp/a b.txt".into(),
            size: 1234,
        };
        assert_eq!(XferRequest::parse(&r.encode()), Some(r));
    }

    #[test]
    fn get_roundtrip() {
        let r = XferRequest::Get {
            path: "/etc/motd".into(),
        };
        assert_eq!(XferRequest::parse(&r.encode()), Some(r));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(XferRequest::parse(b"nope"), None);
        assert_eq!(XferRequest::parse(b"PUT x /p"), None); // bad size
        assert_eq!(XferRequest::parse(b"GET "), None); // empty path
    }
}
