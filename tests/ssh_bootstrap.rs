//! End-to-end test of the mosh-style SSH bootstrap.
//!
//! A fake `ssh` program (a shell script) stands in for the real one: instead of
//! connecting to a remote host, it drops the target argument and runs the rest
//! of the command line locally — i.e. it launches the real `noisshd --one-shot`
//! on this machine. The bootstrap then parses the connect line, and a real
//! client connects over Noise/UDP and runs the shell.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use auth::KnownHosts;
use noise_core::generate_keypair;
use noissh::client::Client;
use noissh::ssh;
use predict::DisplayMode;

#[test]
fn ssh_bootstrap_then_session() {
    let noisshd = env!("CARGO_BIN_EXE_noisshd");

    // Write a fake `ssh` that runs the command locally and appends a
    // deterministic one-shot command.
    let dir = std::env::temp_dir().join(format!("noissh-ssh-test-{}", std::process::id()));
    let _ = fs::create_dir_all(&dir);
    let fake_ssh = dir.join("fake-ssh");
    fs::write(
        &fake_ssh,
        "#!/bin/sh\n\
         # args: <target> <noisshd> --one-shot --authorize <pub>\n\
         shift  # drop the ssh target\n\
         exec \"$@\" --command /bin/sh -c 'printf \"SSH-BOOT-OK\\n\"; sleep 0.8'\n",
    )
    .unwrap();
    fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o755)).unwrap();

    // SAFETY: single-threaded test setup before any threads are spawned.
    unsafe {
        std::env::set_var("NOISSH_SSH", &fake_ssh);
    }

    let client_kp = generate_keypair().unwrap();

    // Bootstrap: the fake ssh launches noisshd --one-shot locally.
    let boot = ssh::bootstrap("127.0.0.1", &[noisshd.to_string()], &client_kp.public, &[])
        .expect("bootstrap");

    // Pin the server key (delivered over the trusted SSH channel).
    let mut known = KnownHosts::new();
    let label = format!("127.0.0.1:{}", boot.server_addr.port());
    known.check_or_add(
        &label,
        &auth::PublicKey::from_bytes(&boot.server_pubkey).unwrap(),
    );

    let mut client = Client::connect(
        &client_kp,
        known,
        label,
        boot.server_addr,
        10,
        40,
        DisplayMode::Adaptive,
    )
    .expect("connect");

    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        client.pump_once().unwrap();
        if client.core().screen().row_text(0).contains("SSH-BOOT-OK") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "bootstrap session produced no output"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(client.core().screen().row_text(0), "SSH-BOOT-OK");

    let _ = fs::remove_dir_all(&dir);
}
