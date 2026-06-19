//! Real-socket end-to-end test of file transfer (`--put` / `--get`): bytes ride
//! a reliable session stream over real UDP, written/read on disk by the driver's
//! `FileSink`/`FileSource`. Integrity is guaranteed by the authenticated stream.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use auth::{AuthorizedKeys, KnownHosts, PublicKey};
use noise_core::{Keypair, generate_keypair};
use noissh::client::Client;
use noissh::server::{Server, ServerCore};
use predict::DisplayMode;
use proto::XferRequest;
use pty::LocalLogin;

/// A unique temp path under the OS temp dir for this process.
fn temp_path(tag: &str) -> std::path::PathBuf {
    let pid = std::process::id();
    std::env::temp_dir().join(format!("noissh-xfer-{tag}-{pid}.bin"))
}

/// A running noisshd plus everything a client needs to reach it.
struct TestServer {
    addr: std::net::SocketAddr,
    server_pub: Vec<u8>,
    client_kp: Keypair,
    stop: Arc<AtomicBool>,
    handle: thread::JoinHandle<()>,
}

/// Start a transfer-capable noisshd on a background thread.
fn start_server() -> TestServer {
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let server_pub = server_kp.public.clone();
    let mut authorized = AuthorizedKeys::new();
    authorized.add(PublicKey::from_bytes(&client_kp.public).unwrap(), "t");

    let core = ServerCore::new(server_kp, authorized, Box::new(LocalLogin), None);
    let mut server = Server::bind("127.0.0.1:0".parse().unwrap(), core).unwrap();
    let addr = server.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let handle = thread::spawn(move || {
        while !stop2.load(Ordering::SeqCst) {
            if !server.poll_once() {
                break;
            }
        }
    });
    TestServer {
        addr,
        server_pub,
        client_kp,
        stop,
        handle,
    }
}

impl TestServer {
    /// Connect a non-shell client with the server key pre-pinned.
    fn connect(&self) -> Client {
        let label = format!("127.0.0.1:{}", self.addr.port());
        let mut kh = KnownHosts::new();
        kh.check_or_add(&label, &PublicKey::from_bytes(&self.server_pub).unwrap());
        Client::connect_with(
            &self.client_kp,
            kh,
            label,
            self.addr,
            10,
            40,
            DisplayMode::Adaptive,
            false,
            None,
            Duration::from_secs(5),
        )
        .unwrap()
    }

    fn shutdown(self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.handle.join();
    }
}

#[test]
fn put_uploads_a_file_to_the_server() {
    let server = start_server();
    let mut client = server.connect();

    let local = temp_path("put-src");
    let remote = temp_path("put-dst");
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&local, &payload).unwrap();
    let _ = std::fs::remove_file(&remote);

    let req = XferRequest::Put {
        path: remote.to_string_lossy().into_owned(),
        size: payload.len() as u64,
    };
    client
        .run_transfer(&req, &local.to_string_lossy())
        .expect("put transfer failed");

    server.shutdown();

    let written = std::fs::read(&remote).expect("server never wrote the file");
    assert_eq!(written, payload, "uploaded bytes differ from source");

    let _ = std::fs::remove_file(&local);
    let _ = std::fs::remove_file(&remote);
}

#[test]
fn get_downloads_a_file_from_the_server() {
    let server = start_server();
    let mut client = server.connect();

    let remote = temp_path("get-src");
    let local = temp_path("get-dst");
    let payload: Vec<u8> = (0..123_457u32).map(|i| (i % 253) as u8).collect();
    std::fs::write(&remote, &payload).unwrap();
    let _ = std::fs::remove_file(&local);

    let req = XferRequest::Get {
        path: remote.to_string_lossy().into_owned(),
    };
    client
        .run_transfer(&req, &local.to_string_lossy())
        .expect("get transfer failed");

    server.shutdown();

    let downloaded = std::fs::read(&local).expect("client never wrote the file");
    assert_eq!(downloaded, payload, "downloaded bytes differ from source");

    let _ = std::fs::remove_file(&local);
    let _ = std::fs::remove_file(&remote);
}

#[test]
fn put_to_uncreatable_destination_is_reported_as_an_error() {
    let server = start_server();
    let mut client = server.connect();

    let local = temp_path("put-bad-src");
    std::fs::write(&local, b"hello").unwrap();
    // A destination whose parent directory does not exist: the server can't
    // create the sink and must abort the transfer.
    let remote = "/noissh-no-such-dir-xyz/dst.bin".to_string();

    let req = XferRequest::Put {
        path: remote,
        size: 5,
    };
    let result = client.run_transfer(&req, &local.to_string_lossy());

    server.shutdown();

    assert!(
        result.is_err(),
        "uploading to an uncreatable path should error"
    );

    let _ = std::fs::remove_file(&local);
}

#[test]
fn file_transfer_is_refused_when_privsep_user_is_configured() {
    // With a privsep target user, the driver can't confine file I/O to that
    // user, so transfers must be refused rather than run as the driver's
    // identity. (No real privilege drop happens here — the gate is the presence
    // of a configured user — so this needs no root and never spawns a shell.)
    let server_kp = generate_keypair().unwrap();
    let client_kp = generate_keypair().unwrap();
    let mut authorized = AuthorizedKeys::new();
    authorized.add(PublicKey::from_bytes(&client_kp.public).unwrap(), "t");
    let server_pub = server_kp.public.clone();

    let core = ServerCore::new(server_kp, authorized, Box::new(LocalLogin), None)
        .with_user(Some("some-other-user".to_string()));
    let mut server = Server::bind("127.0.0.1:0".parse().unwrap(), core).unwrap();
    let addr = server.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let handle = thread::spawn(move || {
        while !stop2.load(Ordering::SeqCst) {
            if !server.poll_once() {
                break;
            }
        }
    });

    let remote = temp_path("privsep-src");
    let local = temp_path("privsep-dst");
    std::fs::write(&remote, b"secret").unwrap();
    let _ = std::fs::remove_file(&local);

    let label = format!("127.0.0.1:{}", addr.port());
    let mut kh = KnownHosts::new();
    kh.check_or_add(&label, &PublicKey::from_bytes(&server_pub).unwrap());
    let mut client = Client::connect_with(
        &client_kp,
        kh,
        label,
        addr,
        10,
        40,
        DisplayMode::Adaptive,
        false,
        None,
        Duration::from_secs(5),
    )
    .unwrap();

    let req = XferRequest::Get {
        path: remote.to_string_lossy().into_owned(),
    };
    let result = client.run_transfer(&req, &local.to_string_lossy());

    stop.store(true, Ordering::SeqCst);
    let _ = handle.join();

    assert!(result.is_err(), "transfer must be refused under privsep");
    // The destination must not have been created with the server's identity.
    assert!(
        !std::path::Path::new(&local).exists() || std::fs::read(&local).unwrap().is_empty(),
        "no data should have been written under privsep"
    );

    let _ = std::fs::remove_file(&remote);
    let _ = std::fs::remove_file(&local);
}

#[test]
fn get_of_missing_file_is_reported_as_an_error() {
    let server = start_server();
    let mut client = server.connect();

    let local = temp_path("get-missing-dst");
    let missing = temp_path("does-not-exist");
    let _ = std::fs::remove_file(&local);
    let _ = std::fs::remove_file(&missing);

    let req = XferRequest::Get {
        path: missing.to_string_lossy().into_owned(),
    };
    let result = client.run_transfer(&req, &local.to_string_lossy());

    server.shutdown();

    assert!(result.is_err(), "downloading a missing file should error");

    let _ = std::fs::remove_file(&local);
}
