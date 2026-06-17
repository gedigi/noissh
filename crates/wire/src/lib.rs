//! Wire frame codec for noissh.
//!
//! Defines the plaintext frame format carried inside each Noise-encrypted
//! datagram. Reserves both datagram (v1) and stream (v2) frame classes from
//! day one so v2 needs no protocol break.

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

/// Stream kinds for v2 multiplexed streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// A shell/exec channel.
    Session = 0,
    /// A forwarded TCP connection (-L/-R).
    Forward = 1,
    /// File-transfer subsystem.
    FileTransfer = 2,
    /// Agent-forwarding socket proxy.
    Agent = 3,
}

impl StreamKind {
    fn from_u8(v: u8) -> Result<Self, WireError> {
        Ok(match v {
            0 => StreamKind::Session,
            1 => StreamKind::Forward,
            2 => StreamKind::FileTransfer,
            3 => StreamKind::Agent,
            other => return Err(WireError::UnknownFrame(other)),
        })
    }
}

/// A single protocol frame. Many frames are packed into one datagram payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    // --- v1 datagram class ---
    /// Acknowledge the highest contiguous state-sync sequence applied.
    Ack {
        seq: u64,
    },
    /// Client keystroke bytes as a reliable append-only stream from `offset`.
    Input {
        offset: u64,
        data: Vec<u8>,
    },
    /// Latest-wins terminal state diff: `seq` is this state's id, `base` is the
    /// state id it was diffed against (0 = full snapshot).
    StateDiff {
        seq: u64,
        base: u64,
        data: Vec<u8>,
    },
    /// Window resize.
    Resize {
        cols: u16,
        rows: u16,
    },
    /// Liveness probe carrying an opaque timestamp.
    Ping {
        stamp: u64,
    },
    Pong {
        stamp: u64,
    },

    // --- v2 stream class ---
    StreamOpen {
        id: u64,
        kind: StreamKind,
        meta: Vec<u8>,
    },
    StreamData {
        id: u64,
        offset: u64,
        data: Vec<u8>,
        fin: bool,
    },
    StreamAck {
        id: u64,
        ack: u64,
        window: u32,
    },
    StreamClose {
        id: u64,
        status: i32,
    },
    StreamReset {
        id: u64,
    },

    // --- control ---
    /// Opaque control-channel message (proto crate defines payload).
    Control {
        data: Vec<u8>,
    },
}

// Frame type tags.
const T_ACK: u8 = 0x01;
const T_INPUT: u8 = 0x02;
const T_STATEDIFF: u8 = 0x03;
const T_RESIZE: u8 = 0x04;
const T_PING: u8 = 0x05;
const T_PONG: u8 = 0x06;
const T_STREAM_OPEN: u8 = 0x10;
const T_STREAM_DATA: u8 = 0x11;
const T_STREAM_ACK: u8 = 0x12;
const T_STREAM_CLOSE: u8 = 0x13;
const T_STREAM_RESET: u8 = 0x14;
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
            Frame::Input { offset, data } => {
                out.push(T_INPUT);
                put_varint(out, *offset);
                put_bytes(out, data);
            }
            Frame::StateDiff { seq, base, data } => {
                out.push(T_STATEDIFF);
                put_varint(out, *seq);
                put_varint(out, *base);
                put_bytes(out, data);
            }
            Frame::Resize { cols, rows } => {
                out.push(T_RESIZE);
                put_varint(out, *cols as u64);
                put_varint(out, *rows as u64);
            }
            Frame::Ping { stamp } => {
                out.push(T_PING);
                put_varint(out, *stamp);
            }
            Frame::Pong { stamp } => {
                out.push(T_PONG);
                put_varint(out, *stamp);
            }
            Frame::StreamOpen { id, kind, meta } => {
                out.push(T_STREAM_OPEN);
                put_varint(out, *id);
                out.push(*kind as u8);
                put_bytes(out, meta);
            }
            Frame::StreamData {
                id,
                offset,
                data,
                fin,
            } => {
                out.push(T_STREAM_DATA);
                put_varint(out, *id);
                put_varint(out, *offset);
                out.push(if *fin { 1 } else { 0 });
                put_bytes(out, data);
            }
            Frame::StreamAck { id, ack, window } => {
                out.push(T_STREAM_ACK);
                put_varint(out, *id);
                put_varint(out, *ack);
                put_varint(out, *window as u64);
            }
            Frame::StreamClose { id, status } => {
                out.push(T_STREAM_CLOSE);
                put_varint(out, *id);
                // zig-zag encode signed status
                put_varint(out, zigzag(*status as i64));
            }
            Frame::StreamReset { id } => {
                out.push(T_STREAM_RESET);
                put_varint(out, *id);
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
                offset: get_varint(buf, pos)?,
                data: get_bytes(buf, pos)?,
            },
            T_STATEDIFF => Frame::StateDiff {
                seq: get_varint(buf, pos)?,
                base: get_varint(buf, pos)?,
                data: get_bytes(buf, pos)?,
            },
            T_RESIZE => Frame::Resize {
                cols: get_varint(buf, pos)? as u16,
                rows: get_varint(buf, pos)? as u16,
            },
            T_PING => Frame::Ping {
                stamp: get_varint(buf, pos)?,
            },
            T_PONG => Frame::Pong {
                stamp: get_varint(buf, pos)?,
            },
            T_STREAM_OPEN => Frame::StreamOpen {
                id: get_varint(buf, pos)?,
                kind: StreamKind::from_u8(get_u8(buf, pos)?)?,
                meta: get_bytes(buf, pos)?,
            },
            T_STREAM_DATA => {
                let id = get_varint(buf, pos)?;
                let offset = get_varint(buf, pos)?;
                let fin = get_u8(buf, pos)? != 0;
                let data = get_bytes(buf, pos)?;
                Frame::StreamData {
                    id,
                    offset,
                    data,
                    fin,
                }
            }
            T_STREAM_ACK => Frame::StreamAck {
                id: get_varint(buf, pos)?,
                ack: get_varint(buf, pos)?,
                window: get_varint(buf, pos)? as u32,
            },
            T_STREAM_CLOSE => Frame::StreamClose {
                id: get_varint(buf, pos)?,
                status: unzigzag(get_varint(buf, pos)?) as i32,
            },
            T_STREAM_RESET => Frame::StreamReset {
                id: get_varint(buf, pos)?,
            },
            T_CONTROL => Frame::Control {
                data: get_bytes(buf, pos)?,
            },
            other => return Err(WireError::UnknownFrame(other)),
        })
    }
}

fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

fn unzigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
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
            offset: 1000,
            data: b"hello world".to_vec(),
        });
        roundtrip(Frame::StateDiff {
            seq: 9,
            base: 8,
            data: vec![0, 1, 2, 255],
        });
        roundtrip(Frame::Resize { cols: 80, rows: 24 });
        roundtrip(Frame::Ping { stamp: 123456789 });
        roundtrip(Frame::Pong { stamp: 987654321 });
        roundtrip(Frame::StreamOpen {
            id: 3,
            kind: StreamKind::Forward,
            meta: b"127.0.0.1:22".to_vec(),
        });
        roundtrip(Frame::StreamData {
            id: 3,
            offset: 4096,
            data: vec![7; 100],
            fin: true,
        });
        roundtrip(Frame::StreamData {
            id: 3,
            offset: 0,
            data: vec![],
            fin: false,
        });
        roundtrip(Frame::StreamAck {
            id: 3,
            ack: 4096,
            window: 65535,
        });
        roundtrip(Frame::StreamClose { id: 3, status: 0 });
        roundtrip(Frame::StreamClose { id: 3, status: -1 });
        roundtrip(Frame::StreamClose { id: 3, status: 137 });
        roundtrip(Frame::StreamReset { id: 3 });
        roundtrip(Frame::Control {
            data: b"open-shell".to_vec(),
        });
    }

    #[test]
    fn multiple_frames_in_one_payload() {
        let frames = vec![
            Frame::Ack { seq: 1 },
            Frame::Input {
                offset: 0,
                data: b"ls\n".to_vec(),
            },
            Frame::Resize {
                cols: 120,
                rows: 40,
            },
        ];
        let bytes = encode_frames(&frames);
        assert_eq!(decode_frames(&bytes).unwrap(), frames);
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
        // Input frame: tag, offset=0, len=10 but no data
        let buf = [T_INPUT, 0x00, 0x0a];
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

    #[test]
    fn zigzag_roundtrip() {
        for v in [0i64, 1, -1, 137, -137, i32::MAX as i64, i32::MIN as i64] {
            assert_eq!(unzigzag(zigzag(v)), v);
        }
    }
}
