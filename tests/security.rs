//! Security properties: unauthorized keys rejected before any session/PTY work,
//! known_hosts mismatch aborts, and the frame/handshake parsers never panic on
//! malformed input.

use std::net::SocketAddr;

use auth::{AuthorizedKeys, KnownHosts, PublicKey, Tofu};
use noise_core::generate_keypair;
use noissh::client::ClientCore;
use noissh::server::ServerCore;
use predict::DisplayMode;
use pty::LocalLogin;

/// Drive a client/server handshake in-process and return whether a server-side
/// session was created (i.e. the client was authorized).
fn handshake_creates_session(authorize_client: bool) -> bool {
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();

    let mut authorized = AuthorizedKeys::new();
    if authorize_client {
        authorized.add(PublicKey::from_bytes(&client_kp.public).unwrap(), "ok");
    }

    let mut server = ServerCore::new(
        server_kp,
        authorized,
        Box::new(LocalLogin),
        Some(vec!["/bin/sh".into(), "-c".into(), "printf X".into()]),
    );

    let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let (mut client, first) = ClientCore::new(
        &client_kp,
        KnownHosts::new(),
        "h:1",
        addr,
        10,
        40,
        DisplayMode::Adaptive,
    )
    .unwrap();

    // Run the handshake to completion.
    let mut to_server = vec![first];
    for _ in 0..10 {
        let mut to_client = Vec::new();
        for pkt in to_server.drain(..) {
            for (_a, out) in server.handle_packet(addr, &pkt) {
                to_client.push(out);
            }
        }
        for pkt in to_client {
            if let Ok(replies) = client.handle_packet(&pkt) {
                to_server.extend(replies);
            }
        }
        for pkt in client.tick() {
            to_server.push(pkt);
        }
        if server.session_count() > 0 {
            break;
        }
    }
    server.session_count() > 0
}

#[test]
fn authorized_client_creates_session() {
    assert!(handshake_creates_session(true));
}

#[test]
fn unauthorized_client_creates_no_session() {
    // The unauthorized client's key is rejected at handshake completion, before
    // any session or PTY work happens.
    assert!(!handshake_creates_session(false));
}

#[test]
fn known_hosts_mismatch_is_detected() {
    let mut known = KnownHosts::new();
    let real = PublicKey([1u8; 32]);
    let attacker = PublicKey([2u8; 32]);
    assert_eq!(known.check_or_add("host", &real), Tofu::New);
    assert_eq!(known.check_or_add("host", &attacker), Tofu::Mismatch);
}

#[test]
fn malformed_packets_never_panic_the_server() {
    let server_kp = generate_keypair().unwrap();
    let mut server = ServerCore::new(
        server_kp,
        AuthorizedKeys::new(),
        Box::new(LocalLogin),
        Some(vec!["/bin/sh".into()]),
    );
    let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();

    // Deterministic fuzz of arbitrary datagrams — must never panic.
    let mut state = 0xCAFEBABEu64;
    for _ in 0..20000 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let len = (state >> 56) as usize % 200;
        let mut buf = Vec::with_capacity(len);
        let mut s = state;
        for _ in 0..len {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            buf.push((s >> 33) as u8);
        }
        let _ = server.handle_packet(addr, &buf); // must not panic
    }
}

#[test]
fn forged_transport_packet_is_rejected() {
    // A handshake establishes a real session; then we corrupt a sealed packet
    // and confirm the server rejects it (no frames processed, no panic).
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let mut authorized = AuthorizedKeys::new();
    authorized.add(PublicKey::from_bytes(&client_kp.public).unwrap(), "ok");

    let mut server = ServerCore::new(
        server_kp,
        authorized,
        Box::new(LocalLogin),
        Some(vec!["/bin/sh".into(), "-c".into(), "printf X".into()]),
    );
    let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let (mut client, first) = ClientCore::new(
        &client_kp,
        KnownHosts::new(),
        "h:1",
        addr,
        10,
        40,
        DisplayMode::Adaptive,
    )
    .unwrap();

    let mut to_server = vec![first];
    for _ in 0..10 {
        let mut to_client = Vec::new();
        for pkt in to_server.drain(..) {
            for (_a, out) in server.handle_packet(addr, &pkt) {
                to_client.push(out);
            }
        }
        for pkt in to_client {
            if let Ok(replies) = client.handle_packet(&pkt) {
                to_server.extend(replies);
            }
        }
        for pkt in client.tick() {
            to_server.push(pkt);
        }
    }
    assert!(server.session_count() > 0);

    // Take a legitimate client packet, corrupt its ciphertext, and feed it from
    // a DIFFERENT source address. It must be rejected (auth fails) and must NOT
    // move the session's peer address.
    if let Some(mut pkt) = client.tick().into_iter().next() {
        let last = pkt.len() - 1;
        pkt[last] ^= 0xff;
        let evil: SocketAddr = "198.51.100.66:9".parse().unwrap();
        let out = server.handle_packet(evil, &pkt);
        // No reply should be produced for a forged packet.
        assert!(out.is_empty());
    }
}

#[test]
fn injected_garbage_does_not_kill_inflight_handshake() {
    // The session id is plaintext, so an attacker could try to abort an
    // in-progress handshake by injecting a packet with that id. A bogus packet
    // must NOT destroy the pending state: the legitimate handshake still
    // completes.
    use transport::build_handshake_packet;

    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let mut authorized = AuthorizedKeys::new();
    authorized.add(PublicKey::from_bytes(&client_kp.public).unwrap(), "ok");
    let mut server = ServerCore::new(server_kp, authorized, Box::new(LocalLogin), None);
    let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();

    let (mut client, first) = ClientCore::new(
        &client_kp,
        KnownHosts::new(),
        "h:1",
        addr,
        10,
        40,
        DisplayMode::Adaptive,
    )
    .unwrap();
    let mut sid = [0u8; 8];
    sid.copy_from_slice(&first[1..9]);

    // msg1 -> server creates pending state and replies msg2.
    let reply = server.handle_packet(addr, &first);
    assert!(!reply.is_empty(), "server should answer msg1");

    // Attacker injects a (large enough to pass the floor) garbage packet for the
    // same session id from a different address; it must be ignored.
    let garbage = build_handshake_packet(&sid, &vec![7u8; 1300]);
    assert!(
        server
            .handle_packet("198.51.100.9:1".parse().unwrap(), &garbage)
            .is_empty()
    );

    // The legitimate client finishes the handshake; a session must result.
    let mut to_client: Vec<Vec<u8>> = reply.into_iter().map(|(_, p)| p).collect();
    for _ in 0..10 {
        let mut next = Vec::new();
        for pkt in to_client.drain(..) {
            if let Ok(reps) = client.handle_packet(&pkt) {
                for r in reps {
                    for (_a, o) in server.handle_packet(addr, &r) {
                        next.push(o);
                    }
                }
            }
        }
        for p in client.tick() {
            for (_a, o) in server.handle_packet(addr, &p) {
                next.push(o);
            }
        }
        to_client = next;
        if server.session_count() > 0 {
            break;
        }
    }
    assert_eq!(
        server.session_count(),
        1,
        "garbage injection destroyed the in-flight handshake"
    );
}

#[test]
fn undersized_handshake_init_gets_no_reply() {
    // Anti-amplification: a small, unpadded new-session init must not draw the
    // (larger) handshake reply, and must not create state. A properly padded
    // init from a real client does get a reply.
    use transport::{build_handshake_packet, random_session_id};

    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let mut authorized = AuthorizedKeys::new();
    authorized.add(PublicKey::from_bytes(&client_kp.public).unwrap(), "ok");
    let mut server = ServerCore::new(server_kp, authorized, Box::new(LocalLogin), None);
    let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();

    // A tiny init: header + a handful of bytes (well under the floor).
    let sid = random_session_id();
    let small = build_handshake_packet(&sid, &[1, 2, 3, 4, 5]);
    assert!(
        server.handle_packet(addr, &small).is_empty(),
        "server replied to an undersized init (amplification vector)"
    );
    assert_eq!(server.session_count(), 0);

    // A real, padded client init does get a reply.
    let (_client, first) = ClientCore::new(
        &client_kp,
        KnownHosts::new(),
        "h:1",
        addr,
        10,
        40,
        DisplayMode::Adaptive,
    )
    .unwrap();
    assert!(
        first.len() >= transport::MIN_HANDSHAKE_INIT,
        "client init must be padded to the floor"
    );
    assert!(
        !server.handle_packet(addr, &first).is_empty(),
        "server should answer a properly padded init"
    );
}
