#![forbid(unsafe_code)]
//! Protocol wiring for noissh: handshake driver, control channel, and the
//! interactive-shell data plane that ties the Noise core, transport, terminal
//! model, predictive echo, and auth crates together.
//!
//! This crate is I/O-free: it consumes and produces bytes/frames. The binaries
//! add UDP sockets and PTYs.

pub mod control;
pub mod handshake;
pub mod shell;

pub use control::{ControlError, ControlMsg};
pub use handshake::{HandshakeError, Handshaker, HsOutcome};
pub use shell::{ClientShell, ServerShell};

use auth::{AuthorizedKeys, KnownHosts, PublicKey, Tofu};

/// Decide whether a client's authenticated static key is authorized, taking the
/// raw 32-byte key as produced by the handshake.
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
    use noise_core::generate_keypair;
    use transport::random_session_id;

    /// End-to-end handshake + authorization, the way the daemon will run it.
    #[test]
    fn handshake_then_authorize_known_client() {
        let client_kp = generate_keypair().unwrap();
        let server_kp = generate_keypair().unwrap();
        let sid = random_session_id();

        // Server authorizes this client's public key.
        let mut authorized = AuthorizedKeys::new();
        authorized.add(PublicKey::from_bytes(&client_kp.public).unwrap(), "laptop");

        let (mut client, p1) = Handshaker::client(&client_kp.private, sid).unwrap();
        let mut server = Handshaker::server(&server_kp.private, sid).unwrap();

        let p2 = server.read(body(&p1)).unwrap().reply.unwrap();
        let p3 = client.read(body(&p2)).unwrap().reply.unwrap();
        server.read(body(&p3)).unwrap();

        assert!(server.is_finished());
        // The server authorizes the authenticated client key BEFORE any session.
        assert!(authorize_client(
            &authorized,
            &server.remote_static().unwrap()
        ));

        // The client pins the server on first contact (TOFU New).
        let mut known = KnownHosts::new();
        assert_eq!(
            verify_server(&mut known, "host:9999", &client.remote_static().unwrap()),
            Tofu::New
        );
        // Reconnect: same key -> Match.
        assert_eq!(
            verify_server(&mut known, "host:9999", &client.remote_static().unwrap()),
            Tofu::Match
        );
    }

    #[test]
    fn unauthorized_client_is_rejected() {
        let client_kp = generate_keypair().unwrap();
        let server_kp = generate_keypair().unwrap();
        let sid = random_session_id();

        // authorized_keys does NOT contain this client.
        let authorized = AuthorizedKeys::new();

        let (mut client, p1) = Handshaker::client(&client_kp.private, sid).unwrap();
        let mut server = Handshaker::server(&server_kp.private, sid).unwrap();
        let p2 = server.read(body(&p1)).unwrap().reply.unwrap();
        let p3 = client.read(body(&p2)).unwrap().reply.unwrap();
        server.read(body(&p3)).unwrap();

        assert!(!authorize_client(
            &authorized,
            &server.remote_static().unwrap()
        ));
    }

    #[test]
    fn tofu_mismatch_detected() {
        let mut known = KnownHosts::new();
        let real = [1u8; 32];
        let attacker = [2u8; 32];
        assert_eq!(verify_server(&mut known, "h", &real), Tofu::New);
        assert_eq!(verify_server(&mut known, "h", &attacker), Tofu::Mismatch);
    }

    fn body(pkt: &[u8]) -> &[u8] {
        match transport::parse_packet(pkt).unwrap() {
            transport::Packet::Handshake { body, .. } => body,
            _ => panic!("expected handshake packet"),
        }
    }
}
