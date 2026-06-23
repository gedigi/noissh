//! Real-socket end-to-end test of remote commands: the client opens an exec stream for
//! a command; the server runs it under pipes and streams stdout, stderr, and the
//! exit code back. Driven via `ClientCore` so output and the code can be asserted
//! without touching process stdio.

use std::net::UdpSocket;
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
use transport::StreamEvent;
use wire::StreamKind;

#[test]
fn exec_streams_stdout_stderr_and_exit_code() {
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let mut authorized = AuthorizedKeys::new();
    authorized.add(PublicKey::from_bytes(&client_kp.public).unwrap(), "t");

    let core = ServerCore::new(server_kp, authorized, Box::new(LocalLogin), None);
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

    let cmd = "printf OUT; printf ERR >&2; exit 7";
    let mut e: Option<u64> = None;
    let mut err_id: Option<u64> = None;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut code: Option<i32> = None;

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut buf = [0u8; 65536];
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            for p in core.handle_packet(&buf[..n]).unwrap() {
                sock.send_to(&p, server_addr).unwrap();
            }
        }
        if core.is_established() && e.is_none() {
            e = Some(core.open_exec(cmd));
        }
        for ev in core.take_stream_events() {
            match ev {
                StreamEvent::Opened {
                    id,
                    kind: StreamKind::Exec,
                    ..
                } => err_id = Some(id),
                StreamEvent::Closed { id, status } if Some(id) == e => code = Some(status),
                _ => {}
            }
        }
        if let Some(e) = e {
            out.extend_from_slice(&core.stream_read(e));
        }
        if let Some(s) = err_id {
            err.extend_from_slice(&core.stream_read(s));
        }
        for p in core.tick() {
            sock.send_to(&p, server_addr).unwrap();
        }

        let stdout_done = e.map(|e| core.stream_recv_finished(e)).unwrap_or(false);
        let stderr_done = err_id
            .map(|s| core.stream_recv_finished(s))
            .unwrap_or(false);
        if code.is_some() && stdout_done && stderr_done {
            break;
        }
        assert!(Instant::now() < deadline, "exec did not complete in time");
        thread::sleep(Duration::from_millis(2));
    }

    stop.store(true, Ordering::SeqCst);
    let _ = srv.join();

    assert_eq!(out, b"OUT", "stdout mismatch");
    assert_eq!(err, b"ERR", "stderr mismatch");
    assert_eq!(code, Some(7), "exit code mismatch");
}
