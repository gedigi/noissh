#![forbid(unsafe_code)]
//! Frame codec for noissh's session layer.
//!
//! These frames travel inside QUIC (see the main crate's `quic` module):
//! screen-state diffs as QUIC datagrams (or on the control stream when too
//! large), and acks, keystrokes and control messages on the control stream.
//! Each stream of another kind starts with a [`StreamKind`] byte.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("unexpected end of input")]
    UnexpectedEof,
    #[error("unknown frame type {0:#x}")]
    UnknownFrame(u8),
    #[error("varint overflow")]
    VarintOverflow,
    #[error("length exceeds remaining input")]
    BadLength,
    #[error("invalid utf8 in field")]
    BadUtf8,
}

/// What a QUIC stream carries, from the first byte of its header. (Byte 0 is
/// the control stream.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// A forwarded TCP connection (-L/-R/-D).
    Forward = 1,
    /// File-transfer subsystem.
    FileTransfer = 2,
    /// Agent-forwarding socket proxy.
    Agent = 3,
    /// Non-interactive remote command (raw stdin/stdout/stderr, exit status).
    Exec = 4,
}

impl StreamKind {
    /// The kind for a header byte, if it names one.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => StreamKind::Forward,
            2 => StreamKind::FileTransfer,
            3 => StreamKind::Agent,
            4 => StreamKind::Exec,
            _ => return None,
        })
    }
}

/// A session-layer frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Client → server: the highest screen state (`seq`) the client applied.
    Ack { seq: u64 },
    /// Client → server: keystroke bytes for the shell.
    Input { data: Vec<u8> },
    /// Server → client: latest-wins terminal state diff: `seq` is this state's
    /// id, `base` is the state id it was diffed against (0 = full snapshot).
    StateDiff { seq: u64, base: u64, data: Vec<u8> },
    /// Control-channel message (the proto crate defines the payload).
    Control { data: Vec<u8> },
}

// Frame type tags.
const T_ACK: u8 = 0x01;
const T_INPUT: u8 = 0x02;
const T_STATEDIFF: u8 = 0x03;
const T_CONTROL: u8 = 0x20;

/// Append a LEB128 unsigned varint.
pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

/// Read a LEB128 unsigned varint, advancing `pos`.
pub fn get_varint(buf: &[u8], pos: &mut usize) -> Result<u64, WireError> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *buf.get(*pos).ok_or(WireError::UnexpectedEof)?;
        *pos += 1;
        if shift >= 64 || (shift == 63 && (byte & 0x7e) != 0) {
            return Err(WireError::VarintOverflow);
        }
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
}

fn put_bytes(out: &mut Vec<u8>, data: &[u8]) {
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

fn get_bytes(buf: &[u8], pos: &mut usize) -> Result<Vec<u8>, WireError> {
    let len = get_varint(buf, pos)? as usize;
    let end = pos.checked_add(len).ok_or(WireError::BadLength)?;
    if end > buf.len() {
        return Err(WireError::BadLength);
    }
    let out = buf[*pos..end].to_vec();
    *pos = end;
    Ok(out)
}

fn get_u8(buf: &[u8], pos: &mut usize) -> Result<u8, WireError> {
    let b = *buf.get(*pos).ok_or(WireError::UnexpectedEof)?;
    *pos += 1;
    Ok(b)
}

impl Frame {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Frame::Ack { seq } => {
                out.push(T_ACK);
                put_varint(out, *seq);
            }
            Frame::Input { data } => {
                out.push(T_INPUT);
                put_bytes(out, data);
            }
            Frame::StateDiff { seq, base, data } => {
                out.push(T_STATEDIFF);
                put_varint(out, *seq);
                put_varint(out, *base);
                put_bytes(out, data);
            }
            Frame::Control { data } => {
                out.push(T_CONTROL);
                put_bytes(out, data);
            }
        }
    }

    fn decode(buf: &[u8], pos: &mut usize) -> Result<Frame, WireError> {
        let tag = get_u8(buf, pos)?;
        Ok(match tag {
            T_ACK => Frame::Ack {
                seq: get_varint(buf, pos)?,
            },
            T_INPUT => Frame::Input {
                data: get_bytes(buf, pos)?,
            },
            T_STATEDIFF => Frame::StateDiff {
                seq: get_varint(buf, pos)?,
                base: get_varint(buf, pos)?,
                data: get_bytes(buf, pos)?,
            },
            T_CONTROL => Frame::Control {
                data: get_bytes(buf, pos)?,
            },
            other => return Err(WireError::UnknownFrame(other)),
        })
    }
}

/// Encode a sequence of frames into a payload buffer.
pub fn encode_frames(frames: &[Frame]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in frames {
        f.encode(&mut out);
    }
    out
}

/// Decode a payload buffer into frames. Errors on any malformed input.
pub fn decode_frames(buf: &[u8]) -> Result<Vec<Frame>, WireError> {
    let mut frames = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        frames.push(Frame::decode(buf, &mut pos)?);
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(frame: Frame) {
        let bytes = encode_frames(std::slice::from_ref(&frame));
        let back = decode_frames(&bytes).expect("decode");
        assert_eq!(back, vec![frame]);
    }

    #[test]
    fn varint_roundtrip() {
        for v in [
            0u64,
            1,
            127,
            128,
            300,
            16383,
            16384,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let mut out = Vec::new();
            put_varint(&mut out, v);
            let mut pos = 0;
            assert_eq!(get_varint(&out, &mut pos).unwrap(), v);
            assert_eq!(pos, out.len());
        }
    }

    #[test]
    fn varint_overflow_errors() {
        // 10 bytes of continuation -> overflow
        let buf = [0xff; 11];
        let mut pos = 0;
        assert_eq!(get_varint(&buf, &mut pos), Err(WireError::VarintOverflow));
    }

    #[test]
    fn varint_truncated_errors() {
        let buf = [0x80]; // continuation bit set but no following byte
        let mut pos = 0;
        assert_eq!(get_varint(&buf, &mut pos), Err(WireError::UnexpectedEof));
    }

    #[test]
    fn roundtrip_all_variants() {
        roundtrip(Frame::Ack { seq: 42 });
        roundtrip(Frame::Input {
            data: b"hello world".to_vec(),
        });
        roundtrip(Frame::StateDiff {
            seq: 9,
            base: 8,
            data: vec![0, 1, 2, 255],
        });
        roundtrip(Frame::Control {
            data: b"open-shell".to_vec(),
        });
    }

    #[test]
    fn multiple_frames_in_one_payload() {
        let frames = vec![
            Frame::Ack { seq: 1 },
            Frame::Input {
                data: b"ls\n".to_vec(),
            },
            Frame::Control { data: vec![2, 80] },
        ];
        let bytes = encode_frames(&frames);
        assert_eq!(decode_frames(&bytes).unwrap(), frames);
    }

    #[test]
    fn stream_kinds_round_trip_through_their_byte() {
        for k in [
            StreamKind::Forward,
            StreamKind::FileTransfer,
            StreamKind::Agent,
            StreamKind::Exec,
        ] {
            assert_eq!(StreamKind::from_u8(k as u8), Some(k));
        }
        assert_eq!(StreamKind::from_u8(0), None);
        assert_eq!(StreamKind::from_u8(5), None);
    }

    #[test]
    fn empty_payload_decodes_to_no_frames() {
        assert_eq!(decode_frames(&[]).unwrap(), vec![]);
    }

    #[test]
    fn unknown_frame_type_errors() {
        assert_eq!(decode_frames(&[0xAB]), Err(WireError::UnknownFrame(0xAB)));
    }

    #[test]
    fn truncated_length_prefixed_errors() {
        // Input frame: tag, len=10 but no data
        let buf = [T_INPUT, 0x0a];
        assert_eq!(decode_frames(&buf), Err(WireError::BadLength));
    }

    #[test]
    fn fuzz_corpus_never_panics() {
        // Deterministic pseudo-random byte strings must never panic the decoder.
        let mut state = 0x12345678u64;
        for _ in 0..20000 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let len = (state >> 56) as usize % 64;
            let mut buf = Vec::with_capacity(len);
            let mut s = state;
            for _ in 0..len {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                buf.push((s >> 33) as u8);
            }
            let _ = decode_frames(&buf); // must not panic
        }
    }
}
