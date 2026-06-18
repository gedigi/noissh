//! In-process test of the reliable-stream (port-forwarding) data plane through
//! both cores over the real session framing.

use std::net::SocketAddr;
use std::time::Duration;

use auth::{AuthorizedKeys, KnownHosts, PublicKey};
use noise_core::{Keypair, generate_keypair};
use noissh::client::ClientCore;
use noissh::server::ServerCore;
use predict::DisplayMode;
use pty::LocalLogin;
use transport::{SessionId, StreamEvent};

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
    assert!(c.is_established());
    c
}

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
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn forward_large_payload_is_chunked_under_mtu_and_round_trips() {
    let kp = generate_keypair().unwrap();
    let mut authorized = AuthorizedKeys::new();
    authorized.add(PublicKey::from_bytes(&kp.public).unwrap(), "t");
    let mut server = ServerCore::new(
        generate_keypair().unwrap(),
        authorized,
        Box::new(LocalLogin),
        Some(vec!["/bin/sh".into(), "-c".into(), "sleep 5".into()]),
    );
    let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let mut client = connect(&mut server, &kp, addr);

    let id = client.open_forward("198.51.100.7:80");
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    client.stream_write(id, &payload);

    let mut sid: Option<SessionId> = None;
    let mut got: Vec<u8> = Vec::new();
    let mut max_pkt = 0usize;
    for _ in 0..4000 {
        for pkt in client.tick() {
            max_pkt = max_pkt.max(pkt.len());
            for (a, out) in server.handle_packet(addr, &pkt) {
                if a == addr {
                    max_pkt = max_pkt.max(out.len());
                    let _ = client.handle_packet(&out);
                }
            }
        }
        for (a, out) in server.tick() {
            if a == addr {
                max_pkt = max_pkt.max(out.len());
                let _ = client.handle_packet(&out);
            }
        }
        for (s, ev) in server.take_stream_events() {
            if let StreamEvent::Opened { .. } = ev {
                sid = Some(s);
            }
        }
        if let Some(s) = sid {
            loop {
                let d = server.stream_read(s, id);
                if d.is_empty() {
                    break;
                }
                got.extend_from_slice(&d);
            }
        }
        if got.len() >= payload.len() {
            break;
        }
    }
    assert_eq!(got.len(), payload.len(), "not all bytes arrived");
    assert_eq!(got, payload, "payload corrupted in transit");
    // Every datagram must stay within the MTU budget (plaintext cap + headers).
    assert!(
        max_pkt <= 1300,
        "a datagram of {max_pkt} bytes exceeded the MTU budget"
    );
}

#[test]
fn forward_stream_round_trips_bytes_both_ways() {
    let kp = generate_keypair().unwrap();
    let mut authorized = AuthorizedKeys::new();
    authorized.add(PublicKey::from_bytes(&kp.public).unwrap(), "t");
    let mut server = ServerCore::new(
        generate_keypair().unwrap(),
        authorized,
        Box::new(LocalLogin),
        Some(vec!["/bin/sh".into(), "-c".into(), "sleep 5".into()]),
    );
    let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let mut client = connect(&mut server, &kp, addr);

    // Client opens a forward toward a target and sends bytes.
    let id = client.open_forward("198.51.100.7:80");
    client.stream_write(id, b"GET / HTTP/1.0\r\n");
    pump(&mut server, &mut client, addr, 10);

    // Server surfaces the open (with the target as metadata) and the data.
    let mut sid: Option<SessionId> = None;
    let mut opened_meta: Option<Vec<u8>> = None;
    for (s, ev) in server.take_stream_events() {
        if let StreamEvent::Opened { meta, .. } = ev {
            sid = Some(s);
            opened_meta = Some(meta);
        }
    }
    let sid = sid.expect("server never saw the forward open");
    assert_eq!(opened_meta.as_deref(), Some(&b"198.51.100.7:80"[..]));
    assert_eq!(server.stream_read(sid, id), b"GET / HTTP/1.0\r\n");

    // Server (acting as the forwarded peer) writes a reply back.
    server.stream_write(sid, id, b"HTTP/1.0 200 OK\r\n");
    pump(&mut server, &mut client, addr, 10);
    assert_eq!(client.stream_read(id), b"HTTP/1.0 200 OK\r\n");

    // Closing the client half is observed by the server.
    client.stream_close(id);
    pump(&mut server, &mut client, addr, 10);
    let closed = server
        .take_stream_events()
        .iter()
        .any(|(_, ev)| matches!(ev, StreamEvent::Closed { .. }));
    assert!(closed, "server did not observe the stream close");
}
