//! In-process tests for session reattach, idle reaping, and keepalives.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use auth::{AuthorizedKeys, KnownHosts, PublicKey};
use noise_core::{Keypair, generate_keypair};
use noissh::client::ClientCore;
use noissh::server::ServerCore;
use predict::DisplayMode;
use pty::LocalLogin;

fn server_with(cmd: Vec<String>, client_pub: &[u8]) -> ServerCore {
    let mut authorized = AuthorizedKeys::new();
    authorized.add(PublicKey::from_bytes(client_pub).unwrap(), "test");
    ServerCore::new(
        generate_keypair().unwrap(),
        authorized,
        Box::new(LocalLogin),
        Some(cmd),
    )
}

/// Complete a handshake for a fresh client (using `kp`) against `server` from
/// source address `addr`. Returns the established core.
fn connect(server: &mut ServerCore, kp: &Keypair, addr: SocketAddr) -> ClientCore {
    let dummy: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let (mut c, first) = ClientCore::new(
        kp,
        KnownHosts::new(),
        "h:1",
        dummy,
        10,
        40,
        DisplayMode::Adaptive,
    )
    .unwrap();
    // Run enough rounds that the client establishes AND its final handshake
    // message + initial frames are delivered to the server (so the server
    // actually creates the session — don't stop the instant the client side
    // flips to established).
    let mut to_server = vec![first];
    for _ in 0..12 {
        let mut to_client = Vec::new();
        for pkt in to_server.drain(..) {
            for (a, out) in server.handle_packet(addr, &pkt) {
                if a == addr {
                    to_client.push(out);
                }
            }
        }
        for pkt in to_client {
            if let Ok(replies) = c.handle_packet(&pkt) {
                to_server.extend(replies);
            }
        }
        for pkt in c.tick() {
            to_server.push(pkt);
        }
    }
    assert!(c.is_established(), "handshake did not complete");
    c
}

/// Pump packets between a client and the server (no loss) for `rounds`.
fn pump(server: &mut ServerCore, client: &mut ClientCore, addr: SocketAddr, rounds: usize) {
    for _ in 0..rounds {
        for pkt in client.tick() {
            for (a, out) in server.handle_packet(addr, &pkt) {
                if a == addr {
                    let _ = client.handle_packet(&out);
                }
            }
        }
        for (a, out) in server.tick() {
            if a == addr {
                let _ = client.handle_packet(&out);
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn pump_until_marker(
    server: &mut ServerCore,
    client: &mut ClientCore,
    addr: SocketAddr,
    marker: &str,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        pump(server, client, addr, 5);
        if client.screen().row_text(0).contains(marker) {
            return true;
        }
    }
    false
}

#[test]
fn reattach_resumes_the_same_running_shell() {
    let kp = generate_keypair().unwrap();
    // A shell that prints a marker and stays alive long enough to reattach.
    let mut server = server_with(
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf 'REATTACH-OK\\n'; sleep 5".into(),
        ],
        &kp.public,
    );

    let addr_a: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let mut client_a = connect(&mut server, &kp, addr_a);
    assert!(pump_until_marker(
        &mut server,
        &mut client_a,
        addr_a,
        "REATTACH-OK"
    ));
    assert_eq!(server.session_count(), 1);

    // Client A vanishes (we simply stop driving it). A new client with the SAME
    // key connects from a different address and must reattach to the running
    // shell — seeing its existing screen, not a freshly spawned one.
    let addr_b: SocketAddr = "203.0.113.9:6000".parse().unwrap();
    let mut client_b = connect(&mut server, &kp, addr_b);
    assert!(
        pump_until_marker(&mut server, &mut client_b, addr_b, "REATTACH-OK"),
        "reattached client did not receive the existing shell's screen"
    );
    // The old session was moved onto the new one, not duplicated.
    assert_eq!(server.session_count(), 1);
}

#[test]
fn idle_session_is_reaped() {
    let kp = generate_keypair().unwrap();
    let mut server = server_with(
        vec!["/bin/sh".into(), "-c".into(), "sleep 30".into()],
        &kp.public,
    );
    let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let _client = connect(&mut server, &kp, addr);
    assert_eq!(server.session_count(), 1);

    // No further client activity: after the idle grace the session is reaped.
    // (IDLE_REAP_TICKS is 20_000; pump a bit beyond it.)
    for _ in 0..20_050 {
        server.tick();
    }
    assert_eq!(server.session_count(), 0, "idle session was not reaped");
}

#[test]
fn keepalive_keeps_an_idle_session_alive() {
    let kp = generate_keypair().unwrap();
    let mut server = server_with(
        vec!["/bin/sh".into(), "-c".into(), "sleep 30".into()],
        &kp.public,
    );
    let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let mut client = connect(&mut server, &kp, addr);
    assert_eq!(server.session_count(), 1);

    // Tick well past the reap threshold, but deliver a keepalive periodically;
    // each one resets the idle timer, so the session survives.
    for i in 0..25_000 {
        server.tick();
        if i % 500 == 0
            && let Some(ping) = client.keepalive()
        {
            for (a, pong) in server.handle_packet(addr, &ping) {
                if a == addr {
                    let _ = client.handle_packet(&pong);
                }
            }
        }
    }
    assert_eq!(
        server.session_count(),
        1,
        "keepalive failed to keep the session alive"
    );
}
