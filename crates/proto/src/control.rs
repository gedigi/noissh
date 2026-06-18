//! Control-channel messages carried in [`wire::Frame::Control`].
//!
//! These are session-level requests/notifications distinct from the
//! interactive data plane (state-sync + input).

use thiserror::Error;
use wire::{WireError, get_varint, put_varint};

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
    /// `agent` asks the server to expose an SSH agent socket (`SSH_AUTH_SOCK`)
    /// whose connections are tunnelled back to the client's local agent.
    OpenShell {
        cols: u16,
        rows: u16,
        term: String,
        agent: bool,
    },
    /// Either direction: window resize.
    Resize { cols: u16, rows: u16 },
    /// Server → client: the shell exited with this status.
    Exit { status: i32 },
    /// Optional second-factor prompt (server → client), like keyboard-interactive.
    AuthPrompt { echo: bool, prompt: String },
    /// Optional second-factor response (client → server).
    AuthResponse { data: String },
    /// Client → server: please listen on `bind_port` and forward accepted
    /// connections back to the client, which connects them to `target` (`-R`).
    RemoteForward { bind_port: u16, target: String },
}

const M_OPEN_SHELL: u8 = 1;
const M_RESIZE: u8 = 2;
const M_EXIT: u8 = 3;
const M_AUTH_PROMPT: u8 = 4;
const M_AUTH_RESPONSE: u8 = 5;
const M_REMOTE_FORWARD: u8 = 6;

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
    let s = std::str::from_utf8(&buf[*pos..end])
        .map_err(|_| ControlError::BadUtf8)?
        .to_string();
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
            ControlMsg::OpenShell {
                cols,
                rows,
                term,
                agent,
            } => {
                out.push(M_OPEN_SHELL);
                put_varint(&mut out, *cols as u64);
                put_varint(&mut out, *rows as u64);
                put_str(&mut out, term);
                out.push(*agent as u8);
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
            ControlMsg::RemoteForward { bind_port, target } => {
                out.push(M_REMOTE_FORWARD);
                put_varint(&mut out, *bind_port as u64);
                put_str(&mut out, target);
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
                // `agent` is the last field. If you append another field here,
                // advance `pos` past this byte first (as the other arms do).
                let agent = *buf.get(pos).ok_or(ControlError::Eof)? != 0;
                ControlMsg::OpenShell {
                    cols,
                    rows,
                    term,
                    agent,
                }
            }
            M_RESIZE => {
                let cols = get_varint(buf, &mut pos)? as u16;
                let rows = get_varint(buf, &mut pos)? as u16;
                ControlMsg::Resize { cols, rows }
            }
            M_EXIT => ControlMsg::Exit {
                status: unzigzag(get_varint(buf, &mut pos)?) as i32,
            },
            M_AUTH_PROMPT => {
                let echo = *buf.get(pos).ok_or(ControlError::Eof)? != 0;
                pos += 1;
                let prompt = get_str(buf, &mut pos)?;
                ControlMsg::AuthPrompt { echo, prompt }
            }
            M_AUTH_RESPONSE => ControlMsg::AuthResponse {
                data: get_str(buf, &mut pos)?,
            },
            M_REMOTE_FORWARD => {
                let bind_port = get_varint(buf, &mut pos)? as u16;
                let target = get_str(buf, &mut pos)?;
                ControlMsg::RemoteForward { bind_port, target }
            }
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
        roundtrip(ControlMsg::OpenShell {
            cols: 80,
            rows: 24,
            term: "xterm-256color".into(),
            agent: false,
        });
        roundtrip(ControlMsg::OpenShell {
            cols: 80,
            rows: 24,
            term: "xterm-256color".into(),
            agent: true,
        });
        roundtrip(ControlMsg::Resize {
            cols: 120,
            rows: 40,
        });
        roundtrip(ControlMsg::Exit { status: 0 });
        roundtrip(ControlMsg::Exit { status: 137 });
        roundtrip(ControlMsg::Exit { status: -1 });
        roundtrip(ControlMsg::AuthPrompt {
            echo: false,
            prompt: "Password: ".into(),
        });
        roundtrip(ControlMsg::AuthResponse {
            data: "secret".into(),
        });
        roundtrip(ControlMsg::RemoteForward {
            bind_port: 8080,
            target: "127.0.0.1:80".into(),
        });
    }

    #[test]
    fn unknown_tag_errors() {
        assert_eq!(
            ControlMsg::decode(&[0xff]),
            Err(ControlError::Unknown(0xff))
        );
    }

    #[test]
    fn empty_errors() {
        assert_eq!(ControlMsg::decode(&[]), Err(ControlError::Eof));
    }
}
