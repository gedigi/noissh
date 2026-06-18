//! End-to-end test of auto-installing `noisshd` during the SSH bootstrap.
//!
//! A stateful fake `ssh` simulates a remote where `noisshd` is initially absent:
//! the first invocation reports "command not found" (exit 127); the installer
//! invocation (recognised by the `install.sh` URL) drops a marker; and the
//! retry — now that the marker exists — runs the real `noisshd`. The bootstrap
//! must detect the missing command, run the installer, retry, and connect.
//!
//! This lives in its own test binary so its process-global `NOISSH_SSH` /
//! `NOISSH_REMOTE_NOISSHD` env vars don't race with other bootstrap tests.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use noise_core::generate_keypair;
use noissh::ssh;

#[test]
fn bootstrap_installs_missing_noisshd_then_connects() {
    let noisshd = env!("CARGO_BIN_EXE_noisshd");

    let dir = std::env::temp_dir().join(format!("noissh-autoinstall-{}", std::process::id()));
    let _ = fs::create_dir_all(&dir);
    let marker = dir.join("installed.marker");
    let _ = fs::remove_file(&marker);
    let fake_ssh = dir.join("fake-ssh");

    // The fake ssh: args are `<target> <cmd...>`.
    //  - an installer invocation (contains "install.sh") drops the marker;
    //  - a noisshd invocation before the marker exists fails 127;
    //  - after the marker exists it runs the real noisshd one-shot.
    fs::write(
        &fake_ssh,
        "#!/bin/sh\n\
         all=\"$*\"\n\
         case \"$all\" in\n\
           *install.sh*) : > \"$NOISSH_TEST_MARKER\"; exit 0 ;;\n\
         esac\n\
         if [ ! -f \"$NOISSH_TEST_MARKER\" ]; then\n\
           echo 'sh: 1: noisshd: not found' >&2\n\
           exit 127\n\
         fi\n\
         shift\n\
         exec \"$@\" --command /bin/sh -c 'sleep 1'\n",
    )
    .unwrap();
    fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o755)).unwrap();

    // SAFETY: single-threaded test setup (this binary has one test).
    unsafe {
        std::env::set_var("NOISSH_SSH", &fake_ssh);
        std::env::set_var("NOISSH_TEST_MARKER", &marker);
        // The post-install retry invokes this path instead of ~/.local/bin.
        std::env::set_var("NOISSH_REMOTE_NOISSHD", noisshd);
    }

    let client_kp = generate_keypair().unwrap();

    let boot = ssh::bootstrap(
        "127.0.0.1",
        &["noisshd".to_string()],
        &client_kp.public,
        &[],
        true, // auto-install enabled
    )
    .expect("bootstrap should auto-install then connect");

    assert_eq!(boot.server_pubkey.len(), 32, "got a valid server key");
    assert!(boot.server_addr.port() != 0, "got a real UDP port");
    assert!(marker.exists(), "the installer step must have run");

    let _ = fs::remove_dir_all(&dir);
}
