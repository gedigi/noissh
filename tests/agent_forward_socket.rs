//! Real-socket end-to-end test of SSH agent forwarding.
//!
//! A mock "local agent" (a Unix-domain echo socket) stands in for the client's
//! real ssh-agent. The client requests agent forwarding; the server exposes an
//! `SSH_AUTH_SOCK` socket. The test connects to that server-side socket (as a
//! process running inside the session would) and verifies bytes round-trip all
//! the way to the mock agent and back.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
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

/// A mock SSH agent: a Unix socket that echoes whatever it receives.
fn spawn_mock_agent(stop: Arc<AtomicBool>) -> String {
    let path = std::env::temp_dir().join(format!("noissh-mockagent-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let path_str = path.to_string_lossy().into_owned();
    thread::spawn(move || {
        let mut conns: Vec<UnixStream> = Vec::new();
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
        let _ = std::fs::remove_file(&path);
    });
    path_str
}

/// Find the server-side agent socket this process created (glob the temp dir).
fn find_server_agent_sock() -> Option<std::path::PathBuf> {
    let prefix = format!("noissh-agent-{}-", std::process::id());
    let dir = std::env::temp_dir();
    let entries = std::fs::read_dir(&dir).ok()?;
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&prefix) && name.ends_with(".sock") {
            return Some(e.path());
        }
    }
    None
}

#[test]
fn agent_forwarding_round_trips_to_the_local_agent() {
    let agent_stop = Arc::new(AtomicBool::new(false));
    let mock_agent = spawn_mock_agent(agent_stop.clone());

    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let mut authorized = AuthorizedKeys::new();
    authorized.add(PublicKey::from_bytes(&client_kp.public).unwrap(), "t");
    let server_pub = server_kp.public.clone();

    // A shell that just stays alive so the session (and its agent socket) persist.
    let core = ServerCore::new(
        server_kp,
        authorized,
        Box::new(LocalLogin),
        Some(vec!["/bin/sh".into(), "-c".into(), "sleep 30".into()]),
    );
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

    // Client with agent forwarding enabled, bridging to the mock agent.
    let label = format!("127.0.0.1:{}", server_addr.port());
    let mut kh = KnownHosts::new();
    kh.check_or_add(&label, &PublicKey::from_bytes(&server_pub).unwrap());
    let mut client = Client::connect_with(
        &client_kp,
        kh,
        label,
        server_addr,
        24,
        80,
        DisplayMode::Adaptive,
        true,
        Some(mock_agent.clone()),
    )
    .unwrap();
    client.socket().set_nonblocking(true).ok();

    // Drive the client (agent bridge) on a background thread.
    let cli_stop = Arc::new(AtomicBool::new(false));
    let cli_stop2 = cli_stop.clone();
    let cli = thread::spawn(move || {
        let mut next_ka = Instant::now() + Duration::from_secs(1);
        while !cli_stop2.load(Ordering::SeqCst) {
            while client.recv_and_handle().unwrap_or(false) {}
            client.pump_agent();
            client.flush().ok();
            if Instant::now() >= next_ka {
                client.send_keepalive().ok();
                next_ka = Instant::now() + Duration::from_secs(1);
            }
            thread::sleep(Duration::from_millis(3));
        }
    });

    // Wait for the server to bind the agent socket (after it spawns the shell).
    let deadline = Instant::now() + Duration::from_secs(10);
    let agent_sock = loop {
        if let Some(p) = find_server_agent_sock() {
            break Some(p);
        }
        if Instant::now() > deadline {
            break None;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let agent_sock = agent_sock.expect("server never created the agent socket");

    // Act as a process inside the session: connect to SSH_AUTH_SOCK and expect
    // a round-trip through the tunnel to the mock agent.
    let mut got = Vec::new();
    let probe_deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < probe_deadline && got != b"AGENT-PING" {
        if let Ok(mut s) = UnixStream::connect(&agent_sock) {
            s.set_read_timeout(Some(Duration::from_millis(500))).ok();
            if s.write_all(b"AGENT-PING").is_ok() {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf) {
                    got = buf[..n].to_vec();
                }
            }
        }
        if got != b"AGENT-PING" {
            thread::sleep(Duration::from_millis(50));
        }
    }

    cli_stop.store(true, Ordering::SeqCst);
    srv_stop.store(true, Ordering::SeqCst);
    agent_stop.store(true, Ordering::SeqCst);
    let _ = cli.join();
    let _ = srv.join();

    assert_eq!(
        got, b"AGENT-PING",
        "agent bytes did not round-trip through the forward"
    );
}
