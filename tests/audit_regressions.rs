//! Regression tests for the security review of 0.7.0: a hostile server can't
//! make the client dial out, a daemon confined to a command serves nothing
//! else, a new host key isn't trusted silently when the caller asks to be
//! consulted, and removing a key from the authorized set ends its sessions.

use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use auth::{AuthorizedKeys, KnownHosts, PublicKey};
use noise_core::{Keypair, generate_keypair};
use noissh::RuntimeError;
use noissh::client::{Client, ClientCore, StreamEvent};
use noissh::server::{Server, ServerCore};
use predict::DisplayMode;
use pty::LocalLogin;

fn authorized_for(kp: &Keypair) -> AuthorizedKeys {
    let mut a = AuthorizedKeys::new();
    a.add(PublicKey::from_bytes(&kp.public).unwrap(), "t");
    a
}

/// A listener that records whether anything ever connected to it.
fn trap() -> (SocketAddr, Arc<AtomicBool>, Arc<AtomicBool>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let addr = l.local_addr().unwrap();
    let hit = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let (hit2, stop2) = (hit.clone(), stop.clone());
    thread::spawn(move || {
        while !stop2.load(Ordering::SeqCst) {
            if l.accept().is_ok() {
                hit2.store(true, Ordering::SeqCst);
            }
            thread::sleep(Duration::from_millis(2));
        }
    });
    (addr, hit, stop)
}

/// The server names the target of each `-R` connection it forwards back. A
/// hostile server naming a target the client never asked for must not get a
/// connection to it; the target the client did ask for still works.
#[test]
fn client_dials_only_the_remote_forward_targets_it_asked_for() {
    let (wanted, wanted_hit, stop_a) = trap();
    let (unwanted, unwanted_hit, stop_b) = trap();

    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let core = ServerCore::new(
        server_kp,
        authorized_for(&client_kp),
        Box::new(LocalLogin),
        None,
    );
    let mut server = Server::bind("127.0.0.1:0".parse().unwrap(), core).unwrap();
    let server_addr = server.local_addr().unwrap();
    let srv_stop = Arc::new(AtomicBool::new(false));
    let srv_stop2 = srv_stop.clone();
    let (wanted_s, unwanted_s) = (wanted.to_string(), unwanted.to_string());
    let srv = thread::spawn(move || {
        let mut opened = 0;
        while !srv_stop2.load(Ordering::SeqCst) {
            if !server.poll_once() {
                break;
            }
            // The hostile part: once the session is up, open forward streams
            // on our own initiative (the first session's id is 1), first to a
            // target the client never named, then to the one it did.
            if server.core().session_count() > 0 && opened < 2 {
                let target = if opened == 0 { &unwanted_s } else { &wanted_s };
                if server.core_mut().open_forward(1, target).is_some() {
                    opened += 1;
                }
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
    // Port 0: the server picks any port; only the target matters here.
    let remote = vec![(0u16, wanted.to_string())];
    thread::spawn(move || {
        let _ = client.run_forwards(&[], &remote, &[]);
    });

    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline && !wanted_hit.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(10));
    }
    // The unwanted stream was opened first: had the client dialled it, it
    // would have by now. Leave a little more time to be sure.
    thread::sleep(Duration::from_millis(300));
    srv_stop.store(true, Ordering::SeqCst);
    let _ = srv.join();
    stop_a.store(true, Ordering::SeqCst);
    stop_b.store(true, Ordering::SeqCst);

    assert!(
        wanted_hit.load(Ordering::SeqCst),
        "the requested -R target must still be reachable"
    );
    assert!(
        !unwanted_hit.load(Ordering::SeqCst),
        "the client dialled a target the server made up"
    );
}

/// Open an exec stream against `core`'s server and report whether the server
/// reset it (refused) rather than running the command.
fn exec_is_refused(core: ServerCore, client_kp: &Keypair) -> bool {
    let mut server = Server::bind("127.0.0.1:0".parse().unwrap(), core).unwrap();
    let server_addr = server.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let srv = thread::spawn(move || {
        while !stop2.load(Ordering::SeqCst) {
            if !server.poll_once() {
                break;
            }
        }
    });

    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(5)))
        .unwrap();
    let (mut core, first) = ClientCore::new(
        client_kp,
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

    let mut e: Option<u64> = None;
    let mut outcome = None;
    let deadline = Instant::now() + Duration::from_secs(10);
    while outcome.is_none() {
        let mut buf = [0u8; 65536];
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            for p in core.handle_packet(&buf[..n]).unwrap() {
                sock.send_to(&p, server_addr).unwrap();
            }
        }
        if core.is_established() && e.is_none() {
            e = Some(core.open_exec("exit 0"));
        }
        if let Some(e) = e {
            let _ = core.stream_read(e);
        }
        for ev in core.take_stream_events() {
            match ev {
                StreamEvent::Reset { id } if Some(id) == e => outcome = Some(true),
                StreamEvent::Exited { id, .. } if Some(id) == e => outcome = Some(false),
                _ => {}
            }
        }
        for p in core.tick() {
            sock.send_to(&p, server_addr).unwrap();
        }
        assert!(Instant::now() < deadline, "no answer to the exec request");
        thread::sleep(Duration::from_millis(2));
    }
    stop.store(true, Ordering::SeqCst);
    let _ = srv.join();
    outcome.unwrap()
}

#[test]
fn a_daemon_confined_to_a_command_refuses_remote_commands() {
    let client_kp = generate_keypair().unwrap();
    let cmd = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "sleep 1".to_string(),
    ];
    let open = ServerCore::new(
        generate_keypair().unwrap(),
        authorized_for(&client_kp),
        Box::new(LocalLogin),
        Some(cmd.clone()),
    );
    assert!(
        !exec_is_refused(open, &client_kp),
        "exec is served by default"
    );
    let confined = ServerCore::new(
        generate_keypair().unwrap(),
        authorized_for(&client_kp),
        Box::new(LocalLogin),
        Some(cmd),
    )
    .with_restricted(true);
    assert!(confined.extras_refused());
    assert!(exec_is_refused(confined, &client_kp));
}

/// Run packets between an in-process client and server for `rounds`.
fn pump(
    server: &mut ServerCore,
    client: &mut ClientCore,
    addr: SocketAddr,
    first: Vec<u8>,
    rounds: usize,
) -> Result<(), RuntimeError> {
    let mut to_server = vec![first];
    for _ in 0..rounds {
        let mut to_client = Vec::new();
        for pkt in to_server.drain(..) {
            to_client.extend(server.handle_packet(addr, &pkt).into_iter().map(|(_, o)| o));
        }
        to_client.extend(server.tick().into_iter().map(|(_, o)| o));
        for pkt in to_client {
            to_server.extend(client.handle_packet(&pkt)?);
        }
        to_server.extend(client.tick());
        if let Some(e) = client.take_failure() {
            return Err(e);
        }
    }
    Ok(())
}

#[test]
fn an_unknown_host_key_is_reported_not_trusted_when_asked_to() {
    let server_kp = generate_keypair().unwrap();
    let server_pub: [u8; 32] = server_kp.public.clone().try_into().unwrap();
    let client_kp = generate_keypair().unwrap();
    let mut server = ServerCore::new(
        server_kp,
        authorized_for(&client_kp),
        Box::new(LocalLogin),
        Some(vec!["/bin/sh".into(), "-c".into(), "sleep 1".into()]),
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
    client.set_accept_new_hosts(false);

    let err = pump(&mut server, &mut client, addr, first, 10).unwrap_err();
    match err {
        RuntimeError::UnknownHostKey { label, key } => {
            assert_eq!(label, "h:1");
            assert_eq!(key, server_pub, "the caller gets the key to show");
        }
        other => panic!("expected UnknownHostKey, got {other:?}"),
    }
    assert!(!client.is_established());
    assert!(!client.known_hosts_dirty(), "nothing was pinned");
    assert_eq!(
        server.session_count(),
        0,
        "the handshake stopped before the client identified itself"
    );
}

#[test]
fn removing_a_key_ends_its_sessions_and_refuses_new_ones() {
    let client_kp = generate_keypair().unwrap();
    let mut server = ServerCore::new(
        generate_keypair().unwrap(),
        authorized_for(&client_kp),
        Box::new(LocalLogin),
        Some(vec!["/bin/sh".into(), "-c".into(), "sleep 5".into()]),
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
    pump(&mut server, &mut client, addr, first, 10).unwrap();
    assert_eq!(server.session_count(), 1);

    server.set_authorized_keys(AuthorizedKeys::new());
    // The connection is closed and, once it has drained, the session retired.
    let deadline = Instant::now() + Duration::from_secs(10);
    while server.session_count() > 0 {
        let _ = pump(&mut server, &mut client, addr, Vec::new(), 1);
        assert!(Instant::now() < deadline, "the revoked session lingered");
        thread::sleep(Duration::from_millis(20));
    }
    assert!(client.lost_reason().is_some(), "the client was told");

    // And the key no longer gets in.
    let addr2: SocketAddr = "10.0.0.2:5000".parse().unwrap();
    let (mut again, first) = ClientCore::new(
        &client_kp,
        KnownHosts::new(),
        "h:1",
        addr2,
        10,
        40,
        DisplayMode::Adaptive,
    )
    .unwrap();
    let _ = pump(&mut server, &mut again, addr2, first, 10);
    assert_eq!(server.session_count(), 0);
}
