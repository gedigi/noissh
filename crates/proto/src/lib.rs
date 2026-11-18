#![forbid(unsafe_code)]
//! Protocol wiring for noissh's session layer: the control channel, the
//! interactive-shell data plane (terminal model + predictive echo), the file
//! transfer request, and the authentication decisions.
//!
//! This crate is I/O-free: it consumes and produces bytes/frames. The main
//! crate carries them over QUIC and adds sockets and PTYs.

pub mod control;
pub mod shell;
pub mod xfer;

pub use control::{ControlError, ControlMsg};
pub use shell::{ClientShell, ServerShell};
pub use xfer::XferRequest;

use auth::{AuthorizedKeys, KnownHosts, PublicKey, Tofu};

/// Decide whether a client's authenticated static key is authorized, taking the
/// raw 32-byte key as produced by the handshake.
/// The remote command `noissh -T host` runs when no command is given: the
/// user's login shell, reading commands from stdin. A server from 0.8.0 on
/// recognises this exact string and runs the login shell with `-l` itself; an
/// older one hands it to `/bin/sh -c`, where `$SHELL` comes from the server
/// process's environment and `/bin/sh` covers a daemon started without it.
pub const LOGIN_SHELL_COMMAND: &str = "exec \"${SHELL:-/bin/sh}\" -l";

pub fn authorize_client(authorized: &AuthorizedKeys, client_static: &[u8]) -> bool {
    match PublicKey::from_bytes(client_static) {
        Ok(key) => authorized.contains(&key),
        Err(_) => false,
    }
}

/// Run the client's TOFU decision against known_hosts for a server's
/// authenticated static key. Records the pin on first use.
pub fn verify_server(known: &mut KnownHosts, host: &str, server_static: &[u8]) -> Tofu {
    match PublicKey::from_bytes(server_static) {
        Ok(key) => known.check_or_add(host, &key),
        Err(_) => Tofu::Mismatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auth::PublicKey;

    #[test]
    fn authorize_accepts_only_listed_keys() {
        let listed = [7u8; 32];
        let other = [9u8; 32];
        let mut authorized = AuthorizedKeys::new();
        authorized.add(PublicKey::from_bytes(&listed).unwrap(), "laptop");
        assert!(authorize_client(&authorized, &listed));
        assert!(!authorize_client(&authorized, &other));
        // A key of the wrong length is never authorized.
        assert!(!authorize_client(&authorized, &[7u8; 31]));
    }

    #[test]
    fn tofu_pins_then_matches() {
        let mut known = KnownHosts::new();
        let key = [3u8; 32];
        assert_eq!(verify_server(&mut known, "host:9999", &key), Tofu::New);
        assert_eq!(verify_server(&mut known, "host:9999", &key), Tofu::Match);
    }

    #[test]
    fn tofu_mismatch_detected() {
        let mut known = KnownHosts::new();
        let real = [1u8; 32];
        let attacker = [2u8; 32];
        assert_eq!(verify_server(&mut known, "h", &real), Tofu::New);
        assert_eq!(verify_server(&mut known, "h", &attacker), Tofu::Mismatch);
    }
}
