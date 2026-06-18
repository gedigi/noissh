#![forbid(unsafe_code)]
//! noissh runtime: wires the protocol crates into a UDP-driven client and
//! server, plus configuration/key management.
//!
//! The interesting logic lives in socket-free cores ([`server::ServerCore`],
//! [`client::ClientCore`]) so the resilience harness can drive them through an
//! in-memory shim that injects loss/reorder and rewrites source addresses.

pub mod client;
pub mod config;
pub mod forward;
pub mod server;
pub mod socks;
pub mod ssh;
pub mod tty;
pub mod xfer;

use thiserror::Error;

pub use client::{Client, ClientCore};
pub use server::{Server, ServerCore};

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("noise: {0}")]
    Noise(#[from] noise_core::NoiseError),
    #[error("transport: {0}")]
    Transport(#[from] transport::TransportError),
    #[error("handshake: {0}")]
    HandshakeDriver(#[from] proto::HandshakeError),
    #[error("auth parse: {0}")]
    Auth(#[from] auth::AuthError),
    #[error("handshake protocol error")]
    Handshake,
    #[error("HOST KEY MISMATCH for {0} — possible man-in-the-middle; aborting")]
    HostKeyMismatch(String),
    #[error("malformed key file")]
    BadKeyFile,
    #[error("operation timed out")]
    Timeout,
    #[error("SSH bootstrap failed: no connect line from remote noisshd")]
    SshBootstrap,
    #[error("file transfer failed: {0}")]
    Transfer(String),
}
