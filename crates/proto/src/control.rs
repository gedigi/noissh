//! Control-channel messages carried in [`wire::Frame::Control`].
//!
//! These are session-level requests/notifications distinct from the
//! interactive data plane (state-sync + input).

use thiserror::Error;
use wire::{get_varint, put_varint, WireError};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ControlError {
    #[error("wire: {0}")]
    Wire(#[from] WireError),
    #[error("unknown control message {0:#x}")]
    Unknown(u8),
    #[error("unexpected end")]
    Eof,
    #[error("bad utf8")]
    BadUtf8,
}

/// A control-channel message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMsg {
    /// Client → server: request a login shell with this geometry/term.
    OpenShell { cols: u16, rows: u16, term: String },
    /// Either direction: window resize.
    Resize { cols: u16, rows: u16 },
    /// Server → client: the shell exited with this status.
    Exit { status: i32 },
    /// Optional second-factor prompt (server → client), like keyboard-interactive.
    AuthPrompt { echo: bool, prompt: String },
    /// Optional second-factor response (client → server).
    AuthResponse { data: String },
}

const M_OPEN_SHELL: u8 = 1;
const M_RESIZE: u8 = 2;
const M_EXIT: u8 = 3;
const M_AUTH_PROMPT: u8 = 4;
const M_AUTH_RESPONSE: u8 = 5;

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_varint(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

fn get_str(buf: &[u8], pos: &mut usize) -> Result<String, ControlError> {
    let len = get_varint(buf, pos)? as usize;
    let end = pos.checked_add(len).ok_or(ControlError::Eof)?;
    if end > buf.len() {
        return Err(ControlError::Eof);
    }
    let s = std::str::from_utf8(&buf[*pos..end]).map_err(|_| ControlError::BadUtf8)?.to_string();
    *pos = end;
    Ok(s)
}

fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}
fn unzigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

impl ControlMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            ControlMsg::OpenShell { cols, rows, term } => {
                out.push(M_OPEN_SHELL);
                put_varint(&mut out, *cols as u64);
                put_varint(&mut out, *rows as u64);
                put_str(&mut out, term);
            }
            ControlMsg::Resize { cols, rows } => {
                out.push(M_RESIZE);
                put_varint(&mut out, *cols as u64);
                put_varint(&mut out, *rows as u64);
            }
            ControlMsg::Exit { status } => {
                out.push(M_EXIT);
                put_varint(&mut out, zigzag(*status as i64));
            }
            ControlMsg::AuthPrompt { echo, prompt } => {
                out.push(M_AUTH_PROMPT);
                out.push(*echo as u8);
                put_str(&mut out, prompt);
            }
            ControlMsg::AuthResponse { data } => {
                out.push(M_AUTH_RESPONSE);
                put_str(&mut out, data);
            }
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<ControlMsg, ControlError> {
        let tag = *buf.first().ok_or(ControlError::Eof)?;
        let mut pos = 1usize;
        Ok(match tag {
            M_OPEN_SHELL => {
                let cols = get_varint(buf, &mut pos)? as u16;
                let rows = get_varint(buf, &mut pos)? as u16;
                let term = get_str(buf, &mut pos)?;
                ControlMsg::OpenShell { cols, rows, term }
            }
            M_RESIZE => {
                let cols = get_varint(buf, &mut pos)? as u16;
                let rows = get_varint(buf, &mut pos)? as u16;
                ControlMsg::Resize { cols, rows }
            }
            M_EXIT => ControlMsg::Exit { status: unzigzag(get_varint(buf, &mut pos)?) as i32 },
            M_AUTH_PROMPT => {
                let echo = *buf.get(pos).ok_or(ControlError::Eof)? != 0;
                pos += 1;
                let prompt = get_str(buf, &mut pos)?;
                ControlMsg::AuthPrompt { echo, prompt }
            }
            M_AUTH_RESPONSE => ControlMsg::AuthResponse { data: get_str(buf, &mut pos)? },
            other => return Err(ControlError::Unknown(other)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(m: ControlMsg) {
        assert_eq!(ControlMsg::decode(&m.encode()).unwrap(), m);
    }

    #[test]
    fn all_messages_roundtrip() {
        roundtrip(ControlMsg::OpenShell { cols: 80, rows: 24, term: "xterm-256color".into() });
        roundtrip(ControlMsg::Resize { cols: 120, rows: 40 });
        roundtrip(ControlMsg::Exit { status: 0 });
        roundtrip(ControlMsg::Exit { status: 137 });
        roundtrip(ControlMsg::Exit { status: -1 });
        roundtrip(ControlMsg::AuthPrompt { echo: false, prompt: "Password: ".into() });
        roundtrip(ControlMsg::AuthResponse { data: "secret".into() });
    }

    #[test]
    fn unknown_tag_errors() {
        assert_eq!(ControlMsg::decode(&[0xff]), Err(ControlError::Unknown(0xff)));
    }

    #[test]
    fn empty_errors() {
        assert_eq!(ControlMsg::decode(&[]), Err(ControlError::Eof));
    }
}
