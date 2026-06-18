//! Real-socket end-to-end test of `-L`-style local port forwarding: a client
//! opens a forward toward a TCP echo server reachable from the noisshd host;
//! bytes round-trip over real UDP (Noise session) + real TCP.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use auth::{AuthorizedKeys, KnownHosts, PublicKey};
use noise_core::generate_keypair;
use noissh::client::ClientCore;
use noissh::server::{Server, ServerCore};
use predict::DisplayMode;
use pty::LocalLogin;

/// A TCP echo server on 127.0.0.1; returns its address.
fn spawn_echo(stop: Arc<AtomicBool>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let mut conns: Vec<std::net::TcpStream> = Vec::new();
        while !stop.load(Ordering::SeqCst) {
            if let Ok((s, _)) = listener.accept() {
                s.set_nonblocking(true).ok();
                conns.push(s);
            }
            for c in &mut conns {
                let mut buf = [0u8; 4096];
                match c.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        let _ = c.write_all(&buf[..n]);
                    }
                    _ => {}
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
    });
    addr
}

#[test]
fn local_forward_round_trips_over_udp_and_tcp() {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let echo_addr = spawn_echo(echo_stop.clone());

    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let mut authorized = AuthorizedKeys::new();
    authorized.add(PublicKey::from_bytes(&client_kp.public).unwrap(), "t");

    // Forwarding-capable noisshd (no fixed command; forward-only client won't
    // request a shell anyway).
    let core = ServerCore::new(server_kp, authorized, Box::new(LocalLogin), None);
    let mut server = Server::bind("127.0.0.1:0".parse().unwrap(), core).unwrap();
    let server_addr = server.local_addr().unwrap();
    let srv_stop = Arc::new(AtomicBool::new(false));
    let srv_stop2 = srv_stop.clone();
    let srv = thread::spawn(move || {
        while !srv_stop2.load(Ordering::SeqCst) {
            if !server.poll_once() {
                break;
            }
        }
    });

    // Drive a forward-only client by hand.
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(5)))
        .unwrap();
    let (mut core, first) = ClientCore::new(
        &client_kp,
        KnownHosts::new(),
        format!("127.0.0.1:{}", server_addr.port()),
        server_addr,
        10,
        40,
        DisplayMode::Adaptive,
    )
    .unwrap();
    core.set_want_shell(false);
    sock.send_to(&first, server_addr).unwrap();

    let payload = b"hello-through-the-tunnel";
    let mut id: Option<u64> = None;
    let mut got: Vec<u8> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline && got.as_slice() != payload {
        let mut buf = [0u8; 65536];
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            for p in core.handle_packet(&buf[..n]).unwrap() {
                sock.send_to(&p, server_addr).unwrap();
            }
        }
        if core.is_established() && id.is_none() {
            let sid = core.open_forward(&echo_addr.to_string());
            core.stream_write(sid, payload);
            id = Some(sid);
        }
        if let Some(sid) = id {
            let d = core.stream_read(sid);
            got.extend_from_slice(&d);
        }
        for p in core.tick() {
            sock.send_to(&p, server_addr).unwrap();
        }
        thread::sleep(Duration::from_millis(2));
    }

    srv_stop.store(true, Ordering::SeqCst);
    echo_stop.store(true, Ordering::SeqCst);
    let _ = srv.join();

    assert_eq!(got, payload, "bytes did not round-trip through the forward");
}
