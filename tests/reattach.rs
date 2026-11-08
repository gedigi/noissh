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
    // Reattach at once (the first client is silent from here on: it was
    // "restarted").
    let mut server = server_with(
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf 'REATTACH-OK\\n'; sleep 5".into(),
        ],
        &kp.public,
    )
    .with_timeouts(
        Duration::from_secs(60),
        Duration::from_secs(60),
        Duration::ZERO,
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

/// Short timeouts so reaping happens within a test: a 500 ms connection idle
/// timeout and a 300 ms grace for a detached shell.
fn short(server: ServerCore) -> ServerCore {
    server.with_timeouts(
        Duration::from_millis(500),
        Duration::from_millis(300),
        Duration::from_secs(8),
    )
}

#[test]
fn idle_session_is_reaped() {
    let kp = generate_keypair().unwrap();
    let mut server = short(server_with(
        vec!["/bin/sh".into(), "-c".into(), "sleep 30".into()],
        &kp.public,
    ));
    let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let _client = connect(&mut server, &kp, addr);
    assert_eq!(server.session_count(), 1);

    // No further client activity: the connection times out, the shell is kept
    // for the grace period, then the session is reaped.
    let deadline = Instant::now() + Duration::from_secs(5);
    while server.session_count() > 0 && Instant::now() < deadline {
        server.tick();
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(server.session_count(), 0, "idle session was not reaped");
}

#[test]
fn keepalive_keeps_an_idle_session_alive() {
    let kp = generate_keypair().unwrap();
    let mut server = short(server_with(
        vec!["/bin/sh".into(), "-c".into(), "sleep 30".into()],
        &kp.public,
    ));
    let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let mut client = connect(&mut server, &kp, addr);
    assert_eq!(server.session_count(), 1);

    // Well past the idle timeout, with a keepalive every 100 ms: each one
    // resets the idle timer, so the session survives.
    let end = Instant::now() + Duration::from_secs(2);
    while Instant::now() < end {
        server.tick();
        for ping in client.keepalive() {
            for (a, pong) in server.handle_packet(addr, &ping) {
                if a == addr {
                    let _ = client.handle_packet(&pong);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        server.session_count(),
        1,
        "keepalive failed to keep the session alive"
    );
}

#[test]
fn a_second_client_does_not_take_over_a_live_shell() {
    // Two windows with the same key: the second gets its own shell, since the
    // first one's connection is alive (not silent past the reattach window).
    let kp = generate_keypair().unwrap();
    let mut server = server_with(
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf 'SHELL-UP\\n'; sleep 5".into(),
        ],
        &kp.public,
    );
    let addr_a: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let mut client_a = connect(&mut server, &kp, addr_a);
    assert!(pump_until_marker(
        &mut server,
        &mut client_a,
        addr_a,
        "SHELL-UP"
    ));
    let addr_b: SocketAddr = "10.0.0.2:5000".parse().unwrap();
    let mut client_b = connect(&mut server, &kp, addr_b);
    assert!(pump_until_marker(
        &mut server,
        &mut client_b,
        addr_b,
        "SHELL-UP"
    ));
    assert_eq!(server.session_count(), 2);
}

#[test]
fn client_reconnects_after_the_connection_times_out() {
    // An outage longer than the idle timeout ends the QUIC connection on both
    // sides; the client opens a new one and gets the same running shell back.
    let kp = generate_keypair().unwrap();
    let mut server = server_with(
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf 'BEFORE\\n'; read x; printf 'AFTER-%s\\n' \"$x\"; sleep 5".into(),
        ],
        &kp.public,
    )
    .with_timeouts(
        Duration::from_millis(400),
        Duration::from_secs(60),
        Duration::from_secs(8),
    );
    let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let dummy: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let (mut client, first) = ClientCore::with_idle_timeout(
        &kp,
        KnownHosts::new(),
        "h:1",
        dummy,
        10,
        40,
        DisplayMode::Adaptive,
        Duration::from_millis(400),
    )
    .unwrap();
    for (a, out) in server.handle_packet(addr, &first) {
        if a == addr {
            for r in client.handle_packet(&out).unwrap() {
                server.handle_packet(addr, &r);
            }
        }
    }
    assert!(pump_until_marker(&mut server, &mut client, addr, "BEFORE"));

    // Total outage: neither side hears the other; both time out.
    let end = Instant::now() + Duration::from_secs(1);
    while Instant::now() < end {
        let _ = client.tick();
        let _ = server.tick();
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        client.lost_reason().is_some(),
        "client should notice the outage"
    );

    // Reconnect from a new address; the shell is reattached and still running.
    let addr2: SocketAddr = "203.0.113.5:7000".parse().unwrap();
    for pkt in client.reconnect().unwrap() {
        for (a, out) in server.handle_packet(addr2, &pkt) {
            if a == addr2 {
                for r in client.handle_packet(&out).unwrap_or_default() {
                    server.handle_packet(addr2, &r);
                }
            }
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !client.is_connected() && Instant::now() < deadline {
        pump(&mut server, &mut client, addr2, 1);
    }
    assert!(client.is_connected(), "reconnect did not complete");
    client.type_input(b"ok\r");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut seen = false;
    while Instant::now() < deadline && !seen {
        pump(&mut server, &mut client, addr2, 5);
        seen = (0..10).any(|r| client.screen().row_text(r).contains("AFTER-ok"));
    }
    assert!(
        seen,
        "input after reconnect did not reach the original shell"
    );
    assert_eq!(server.session_count(), 1);
}
