//! Real-socket end-to-end test of `-D` dynamic (SOCKS) forwarding: the client
//! runs a local SOCKS5 proxy; a SOCKS5 CONNECT to an echo server is tunnelled
//! through the resilient session and dialled out by the server. Bytes round-trip.

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

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Perform a SOCKS5 CONNECT to `target` over `s`, returning Ok once the success
/// reply is read.
fn socks5_connect(s: &mut TcpStream, target: SocketAddr) -> std::io::Result<()> {
    // Greeting: version 5, 1 method, no-auth (0).
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut greet = [0u8; 2];
    s.read_exact(&mut greet)?;
    assert_eq!(greet, [0x05, 0x00], "server must select no-auth");

    // CONNECT request to an IPv4 target.
    let ip = match target.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => panic!("test uses IPv4"),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req)?;

    // Reply: ver, rep, rsv, atyp, BND.ADDR(4), BND.PORT(2) = 10 bytes for IPv4.
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply)?;
    assert_eq!(reply[0], 0x05, "reply version");
    assert_eq!(reply[1], 0x00, "CONNECT must succeed");
    Ok(())
}

#[test]
fn socks5_dynamic_forward_round_trips() {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let echo_addr = spawn_echo(echo_stop.clone());
    let socks_port = free_port();

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

    let mut client = Client::connect_with(
        &client_kp,
        KnownHosts::new(),
        format!("127.0.0.1:{}", server_addr.port()),
        server_addr,
        10,
        40,
        DisplayMode::Adaptive,
        false,
        None,
        Duration::from_secs(5),
    )
    .unwrap();
    let cli = thread::spawn(move || {
        let _ = client.run_forwards(&[], &[], &[("127.0.0.1".to_string(), socks_port)]);
    });

    let payload = b"socks5-roundtrip";
    let mut got = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut stream: Option<TcpStream> = None;
    while Instant::now() < deadline && got.as_slice() != payload {
        if stream.is_none() {
            match TcpStream::connect(("127.0.0.1", socks_port)) {
                Ok(mut s) => {
                    s.set_read_timeout(Some(Duration::from_millis(300))).ok();
                    if socks5_connect(&mut s, echo_addr).is_ok() {
                        s.write_all(payload).unwrap();
                        stream = Some(s);
                    } else {
                        thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(50)); // proxy not up yet
                    continue;
                }
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
    drop(cli);

    assert_eq!(got, payload, "bytes did not round-trip through SOCKS");
}
