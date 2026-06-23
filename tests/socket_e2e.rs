//! End-to-end tests over real loopback UDP sockets, exercising the actual
//! `Server`/`Client` drivers (handshake, PTY shell, state-sync) and roaming via
//! a real socket rebind mid-session.

use std::net::SocketAddr;
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

struct ServerHandle {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn spawn_server(
    authorized: AuthorizedKeys,
    server_kp: noise_core::Keypair,
    command: Vec<String>,
) -> ServerHandle {
    let core = ServerCore::new(server_kp, authorized, Box::new(LocalLogin), Some(command));
    let mut server = Server::bind("127.0.0.1:0".parse().unwrap(), core).unwrap();
    let addr = server.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let join = thread::spawn(move || {
        while !stop2.load(Ordering::SeqCst) {
            if !server.poll_once() {
                break;
            }
        }
    });
    ServerHandle {
        addr,
        stop,
        join: Some(join),
    }
}

#[test]
fn e2e_shell_output_over_udp() {
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let mut authorized = AuthorizedKeys::new();
    authorized.add(PublicKey::from_bytes(&client_kp.public).unwrap(), "test");

    let srv = spawn_server(
        authorized,
        server_kp,
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf 'E2E-HELLO\\n'; sleep 0.4".into(),
        ],
    );

    let mut client = Client::connect(
        &client_kp,
        KnownHosts::new(),
        format!("127.0.0.1:{}", srv.addr.port()),
        srv.addr,
        10,
        40,
        DisplayMode::Adaptive,
    )
    .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        client.pump_once().unwrap();
        if client.core().screen().row_text(0).contains("E2E-HELLO") {
            break;
        }
        assert!(Instant::now() < deadline, "shell output never arrived");
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(client.core().screen().row_text(0), "E2E-HELLO");
}

#[test]
fn e2e_initial_prompt_appears_without_input() {
    // Regression: an interactive shell prints its prompt with NO trailing newline
    // and then blocks reading a line. The client must SEE that prompt without the
    // user typing anything (the bug was "I have to hit Enter to see the prompt").
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let mut authorized = AuthorizedKeys::new();
    authorized.add(PublicKey::from_bytes(&client_kp.public).unwrap(), "test");

    let srv = spawn_server(
        authorized,
        server_kp,
        vec![
            "/bin/sh".into(),
            "-c".into(),
            // Print a prompt (no newline), then block on read — exactly the
            // shape of a real shell sitting at its first prompt.
            "printf 'PROMPT> '; read _x; printf 'AFTER\\n'".into(),
        ],
    );

    let mut client = Client::connect(
        &client_kp,
        KnownHosts::new(),
        format!("127.0.0.1:{}", srv.addr.port()),
        srv.addr,
        10,
        40,
        DisplayMode::Adaptive,
    )
    .unwrap();

    // Pump only (never type): the prompt must arrive purely from server output.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        client.pump_once().unwrap();
        if client.core().screen().row_text(0).contains("PROMPT>") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "initial prompt never arrived without input"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(client.core().screen().row_text(0), "PROMPT>");
}

#[test]
fn e2e_prompt_after_cursor_query_appears_without_input() {
    // The real bug: a shell's line editor emits a cursor-position query (ESC[6n)
    // at startup and BLOCKS reading the reply before drawing its prompt. If the
    // server never answers, the prompt only appears once the user hits a key
    // (which is misread as the reply). Here the "shell" queries, reads the 6-byte
    // reply (ESC[1;1R), then prints its prompt — all without any client input.
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let mut authorized = AuthorizedKeys::new();
    authorized.add(PublicKey::from_bytes(&client_kp.public).unwrap(), "test");

    let srv = spawn_server(
        authorized,
        server_kp,
        vec![
            "/bin/sh".into(),
            "-c".into(),
            // Put the tty in raw mode (as a real line editor does), query the
            // cursor position, consume the exact 6-byte reply from the pty, then
            // print the prompt. Blocks forever at `dd` if the query is unanswered.
            "stty raw -echo 2>/dev/null; printf '\\033[6n'; dd bs=1 count=6 >/dev/null 2>&1; printf 'PROMPT> '; sleep 0.3".into(),
        ],
    );

    let mut client = Client::connect(
        &client_kp,
        KnownHosts::new(),
        format!("127.0.0.1:{}", srv.addr.port()),
        srv.addr,
        10,
        40,
        DisplayMode::Adaptive,
    )
    .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        client.pump_once().unwrap();
        if client.core().screen().row_text(0).contains("PROMPT>") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "prompt never arrived: cursor-position query went unanswered"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(client.core().screen().row_text(0), "PROMPT>");
}

#[test]
fn e2e_survives_client_rebind_roaming() {
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let mut authorized = AuthorizedKeys::new();
    authorized.add(PublicKey::from_bytes(&client_kp.public).unwrap(), "test");

    // Print A, wait, then B — we roam (rebind) in between.
    let srv = spawn_server(
        authorized,
        server_kp,
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf 'PHASE-A\\n'; sleep 1.0; printf 'PHASE-B\\n'; sleep 0.3".into(),
        ],
    );

    let mut client = Client::connect(
        &client_kp,
        KnownHosts::new(),
        format!("127.0.0.1:{}", srv.addr.port()),
        srv.addr,
        10,
        40,
        DisplayMode::Adaptive,
    )
    .unwrap();

    // Wait for phase A.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        client.pump_once().unwrap();
        if client.core().screen().row_text(0).contains("PHASE-A") {
            break;
        }
        assert!(Instant::now() < deadline, "phase A never arrived");
        thread::sleep(Duration::from_millis(5));
    }

    // Roam: the client jumps to a brand-new source port.
    client.rebind().unwrap();

    // Phase B must still arrive — proving the server followed the new address.
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        client.pump_once().unwrap();
        if client.core().screen().row_text(1).contains("PHASE-B") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "phase B never arrived after roaming"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(client.core().screen().row_text(1), "PHASE-B");
}

#[test]
fn e2e_unauthorized_client_gets_no_session() {
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    // authorized_keys is EMPTY: this client is not allowed.
    let srv = spawn_server(
        AuthorizedKeys::new(),
        server_kp,
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf 'SHOULD-NOT-RUN\\n'".into(),
        ],
    );

    // Connect should fail to establish (handshake completes but server creates
    // no session, so we never get screen state) -> connect times out.
    let result = Client::connect(
        &client_kp,
        KnownHosts::new(),
        format!("127.0.0.1:{}", srv.addr.port()),
        srv.addr,
        10,
        40,
        DisplayMode::Adaptive,
    );
    // The handshake itself completes, so connect() returns established=true; but
    // the server never spawns a shell. Verify no screen output ever appears.
    if let Ok(mut client) = result {
        let deadline = Instant::now() + Duration::from_millis(800);
        while Instant::now() < deadline {
            client.pump_once().unwrap();
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            client.core().screen().row_text(0),
            "",
            "unauthorized client received shell output"
        );
    }
}
