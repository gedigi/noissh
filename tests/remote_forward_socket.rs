//! Real-socket end-to-end test of `-R` remote forwarding: the client asks the
//! server to listen on a port; a TCP connection to that server port is tunnelled
//! back to the client, which dials out to a local echo server. Bytes round-trip.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use auth::{AuthorizedKeys, KnownHosts, PublicKey};
use noise_core::generate_keypair;
use noissh::client::Client;
use noissh::server::{Server, ServerCore};
use predict::DisplayMode;
use pty::LocalLogin;

fn spawn_echo(stop: Arc<AtomicBool>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let mut conns: Vec<TcpStream> = Vec::new();
        while !stop.load(Ordering::SeqCst) {
            if let Ok((s, _)) = listener.accept() {
                s.set_nonblocking(true).ok();
                conns.push(s);
            }
            for c in &mut conns {
                let mut buf = [0u8; 4096];
                if let Ok(n) = c.read(&mut buf)
                    && n > 0
                {
                    let _ = c.write_all(&buf[..n]);
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
    });
    addr
}

/// Find a currently-free TCP port (best effort).
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn remote_forward_round_trips() {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let echo_addr = spawn_echo(echo_stop.clone());
    let rport = free_port();

    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let mut authorized = AuthorizedKeys::new();
    authorized.add(PublicKey::from_bytes(&client_kp.public).unwrap(), "t");

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

    // Forward-only client; request `-R rport -> echo_addr`.
    let mut client = Client::connect_with(
        &client_kp,
        KnownHosts::new(),
        format!("127.0.0.1:{}", server_addr.port()),
        server_addr,
        10,
        40,
        DisplayMode::Adaptive,
        false,
    )
    .unwrap();
    let echo_str = echo_addr.to_string();
    let cli = thread::spawn(move || {
        let _ = client.run_forwards(&[], &[(rport, echo_str)]);
    });

    // Connect to the server's remote-forward port; it should tunnel to echo.
    let payload = b"remote-forward-roundtrip";
    let mut got = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut stream: Option<TcpStream> = None;
    while Instant::now() < deadline && got.as_slice() != payload {
        if stream.is_none() {
            if let Ok(s) = TcpStream::connect(("127.0.0.1", rport)) {
                s.set_read_timeout(Some(Duration::from_millis(200))).ok();
                s.set_nonblocking(false).ok();
                let mut s2 = s.try_clone().unwrap();
                s2.write_all(payload).unwrap();
                stream = Some(s);
            } else {
                thread::sleep(Duration::from_millis(50)); // listener not up yet
                continue;
            }
        }
        if let Some(s) = stream.as_mut() {
            let mut buf = [0u8; 256];
            match s.read(&mut buf) {
                Ok(n) if n > 0 => got.extend_from_slice(&buf[..n]),
                _ => {}
            }
        }
    }

    srv_stop.store(true, Ordering::SeqCst);
    echo_stop.store(true, Ordering::SeqCst);
    let _ = srv.join();
    drop(cli); // detached; process exit reaps it

    assert_eq!(
        got, payload,
        "bytes did not round-trip through the remote forward"
    );
}
