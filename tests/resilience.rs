//! In-process resilience harness.
//!
//! Wires a real `ServerCore` (running a real PTY shell) and a real `ClientCore`
//! through an in-memory shim that injects packet loss + reorder AND rewrites the
//! client's source address mid-session. Server→client packets are delivered
//! ONLY to the client's *current* address, so if session-id roaming were broken
//! the session would stall and the screen would never converge.

use std::net::SocketAddr;

use auth::{AuthorizedKeys, KnownHosts, PublicKey};
use noise_core::generate_keypair;
use noissh::client::ClientCore;
use noissh::server::ServerCore;
use predict::DisplayMode;
use pty::LocalLogin;

/// Tiny deterministic PRNG so the test is reproducible.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    /// Returns true with probability `pct`%.
    fn drop(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

fn run_harness(loss_pct: u64, roam: bool) -> String {
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();

    let mut authorized = AuthorizedKeys::new();
    authorized.add(PublicKey::from_bytes(&client_kp.public).unwrap(), "test");

    let mut server = ServerCore::new(
        server_kp,
        authorized,
        Box::new(LocalLogin),
        Some(vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf 'CONVERGED-OK\\n'; sleep 0.3".into(),
        ]),
    );

    let dummy: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let (mut client, first) = ClientCore::new(
        &client_kp,
        KnownHosts::new(),
        "host:1",
        dummy,
        10,
        40,
        DisplayMode::Adaptive,
    )
    .unwrap();

    let mut rng = Lcg(0x1234_5678);
    let mut client_addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();

    // Queues of in-flight packets.
    let mut to_server: Vec<(SocketAddr, Vec<u8>)> = vec![(client_addr, first)];
    let mut to_client: Vec<Vec<u8>> = Vec::new();

    for round in 0..800 {
        // Roam to a new source address partway through.
        if roam && round == 60 {
            client_addr = "203.0.113.9:41000".parse().unwrap();
        }

        // Client emits its periodic frames.
        for pkt in client.tick() {
            if !rng.drop(loss_pct) {
                to_server.push((client_addr, pkt));
            }
        }
        // Server emits state diffs / exit notices to the *current* peer addr.
        for (addr, pkt) in server.tick() {
            if addr == client_addr && !rng.drop(loss_pct) {
                to_client.push(pkt);
            }
        }

        // Deliver to server in shuffled order (reorder), with loss.
        let mut pending = std::mem::take(&mut to_server);
        while !pending.is_empty() {
            let i = (rng.next() as usize) % pending.len();
            let (src, pkt) = pending.swap_remove(i);
            for (addr, out) in server.handle_packet(src, &pkt) {
                if addr == client_addr && !rng.drop(loss_pct) {
                    to_client.push(out);
                }
            }
        }

        // Deliver to client in shuffled order (reorder), with loss.
        let mut pending = std::mem::take(&mut to_client);
        while !pending.is_empty() {
            let i = (rng.next() as usize) % pending.len();
            let pkt = pending.swap_remove(i);
            if let Ok(replies) = client.handle_packet(&pkt) {
                for r in replies {
                    if !rng.drop(loss_pct) {
                        to_server.push((client_addr, r));
                    }
                }
            }
        }

        if client.screen().row_text(0).contains("CONVERGED-OK") {
            // Drive a few more rounds to drain, then return.
            for _ in 0..20 {
                for (addr, pkt) in server.tick() {
                    if addr == client_addr {
                        let _ = client.handle_packet(&pkt);
                    }
                }
                for pkt in client.tick() {
                    for (addr, out) in server.handle_packet(client_addr, &pkt) {
                        if addr == client_addr {
                            let _ = client.handle_packet(&out);
                        }
                    }
                }
            }
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }

    client.screen().row_text(0)
}

#[test]
fn converges_on_clean_link() {
    assert_eq!(run_harness(0, false), "CONVERGED-OK");
}

#[test]
fn converges_under_heavy_loss_and_reorder() {
    assert_eq!(run_harness(40, false), "CONVERGED-OK");
}

#[test]
fn survives_source_address_change_midsession() {
    // Roaming: the client's source address changes mid-session and the server
    // must follow it for the screen to ever converge.
    assert_eq!(run_harness(20, true), "CONVERGED-OK");
}
