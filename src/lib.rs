#![forbid(unsafe_code)]
//! noissh runtime: wires the protocol crates into a UDP-driven client and
//! server, plus configuration/key management.
//!
//! The interesting logic lives in socket-free cores ([`server::ServerCore`],
//! [`client::ClientCore`]) so the resilience harness can drive them through an
//! in-memory shim that injects loss/reorder and rewrites source addresses.

pub mod client;
pub mod config;
pub mod exec;
pub mod forward;
pub mod server;
pub mod socks;
pub mod ssh;
pub mod sshconfig;
pub mod status;
pub mod tty;
pub mod xfer;

use thiserror::Error;

pub use client::{Client, ClientCore};
pub use server::{Server, ServerCore};

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encryption error: {0}")]
    Noise(#[from] noise_core::NoiseError),
    #[error("transport error: {0}")]
    Transport(#[from] transport::TransportError),
    #[error("handshake error: {0}")]
    HandshakeDriver(#[from] proto::HandshakeError),
    #[error("could not parse a key: {0}")]
    Auth(#[from] auth::AuthError),
    #[error(
        "handshake failed — the server rejected the connection. Check that your key is in the \
         server's authorized_keys (run noissh-keygen to see your public key)."
    )]
    Handshake,
    /// Carries the host:port label; the binary's error printer appends the
    /// known_hosts path and the recovery steps (it knows the config location).
    #[error("host key changed for {0} — possible man-in-the-middle; aborting")]
    HostKeyMismatch(String),
    #[error("malformed key file (expected lines 'private <base64>' and 'public <base64>')")]
    BadKeyFile,
    #[error("the connection timed out")]
    Timeout,
    /// A bad or unresolvable network address, with a complete user-facing reason.
    #[error("{0}")]
    BadAddress(String),
    /// An SSH-bootstrap failure carrying a complete, user-facing reason (often the
    /// remote `ssh`/installer's own error text, or "no connect line" when the
    /// remote server started but printed nothing parseable).
    #[error("{0}")]
    SshFailed(String),
    /// A command-line usage error with a complete, user-facing message. The
    /// binary's printer exits with status 2 for these.
    #[error("{0}")]
    Usage(String),
    #[error("file transfer failed: {0}")]
    Transfer(String),
    #[error("remote command failed: {0}")]
    Exec(String),
}
