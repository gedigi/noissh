//! End-to-end test of noissh standing in for `ssh` under an editor such as VS
//! Code Remote-SSH (`remote.SSH.path`).
//!
//! The editor runs something like `ssh -T -D <port> -o ConnectTimeout=15 host
//! bash`, pipes a bootstrap script into the remote shell over stdin, reads
//! markers back from stdout, and meanwhile tunnels to the server the script
//! started through the `-D` SOCKS proxy of the same connection. This drives the
//! real `noissh` binary that way: a fake `ssh` (as in `ssh_bootstrap.rs`) runs
//! the one-shot `noisshd` locally and records the arguments it was given, so we
//! can also check that ssh-only options reach `ssh` and session-shaping ones
//! don't.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

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

/// SOCKS5 CONNECT to `target` over `s` (no auth, IPv4).
fn socks5_connect(s: &mut TcpStream, target: SocketAddr) -> std::io::Result<()> {
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut greet = [0u8; 2];
    s.read_exact(&mut greet)?;
    let std::net::IpAddr::V4(ip) = target.ip() else {
        panic!("test uses IPv4");
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req)?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply)?;
    if reply[1] != 0 {
        return Err(std::io::Error::other("SOCKS CONNECT refused"));
    }
    Ok(())
}

#[test]
fn noissh_runs_a_command_and_a_socks_forward_like_vscode_remote_ssh() {
    let noissh = env!("CARGO_BIN_EXE_noissh");
    let noisshd = env!("CARGO_BIN_EXE_noisshd");

    let dir = std::env::temp_dir().join(format!("noissh-compat-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let args_log = dir.join("ssh-args");
    let fake_ssh = dir.join("fake-ssh");
    // Log our argv, skip ssh options up to `--`, drop the target, run the rest
    // (the one-shot noisshd) locally.
    fs::write(
        &fake_ssh,
        format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$@\" > '{log}'\n\
             while [ $# -gt 0 ] && [ \"$1\" != \"--\" ]; do shift; done\n\
             shift  # the -- terminator\n\
             shift  # the ssh target\n\
             exec \"$@\"\n",
            log = args_log.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o755)).unwrap();

    let echo_stop = Arc::new(AtomicBool::new(false));
    let echo_addr = spawn_echo(echo_stop.clone());
    let socks_port = free_port();

    // The invocation, shaped like VS Code Remote-SSH's.
    let mut child = Command::new(noissh)
        .args([
            "--server-cmd",
            noisshd,
            "--no-install",
            "-T",
            "-D",
            &socks_port.to_string(),
            "-o",
            "ConnectTimeout=15",
            "-oRemoteCommand=none",
            "-p",
            "2222",
            "127.0.0.1",
            "sh",
        ])
        .env("NOISSH_SSH", &fake_ssh)
        .env("XDG_CONFIG_HOME", &dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn noissh");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (line_tx, line_rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });

    // The "bootstrap script", fed over stdin like an editor does. The shell
    // keeps reading stdin afterwards, so the session stays up.
    stdin.write_all(b"echo REMOTE-READY\n").unwrap();
    stdin.flush().unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match line_rx.recv_timeout(left) {
            Ok(l) if l == "REMOTE-READY" => break,
            Ok(_) => {}
            Err(_) => {
                let _ = child.kill();
                let mut err = String::new();
                let _ = child.stderr.take().unwrap().read_to_string(&mut err);
                panic!("remote command produced no marker; stderr: {err}");
            }
        }
    }

    // While the command runs, the SOCKS forward on the same session works.
    let payload = b"vscode-socks-roundtrip";
    let mut got = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && got.as_slice() != payload {
        got.clear();
        let Ok(mut s) = TcpStream::connect(("127.0.0.1", socks_port)) else {
            thread::sleep(Duration::from_millis(50));
            continue;
        };
        s.set_read_timeout(Some(Duration::from_millis(500))).ok();
        if socks5_connect(&mut s, echo_addr).is_err() || s.write_all(payload).is_err() {
            continue;
        }
        let mut buf = [0u8; 256];
        while got.len() < payload.len() {
            match s.read(&mut buf) {
                Ok(n) if n > 0 => got.extend_from_slice(&buf[..n]),
                _ => break,
            }
        }
    }
    assert_eq!(
        got.as_slice(),
        payload,
        "SOCKS forward did not round-trip alongside the command"
    );

    // Ending the remote shell ends noissh, with the shell's exit status.
    stdin.write_all(b"exit 5\n").unwrap();
    drop(stdin);
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("noissh did not exit after the remote command did");
        }
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(5), "exit status of the remote command");
    echo_stop.store(true, Ordering::SeqCst);

    // ssh-only options reached the bootstrap `ssh`; session-shaping ones (which
    // noissh provides itself) and no-op flags did not.
    let logged = fs::read_to_string(&args_log).unwrap();
    let argv: Vec<&str> = logged.lines().collect();
    assert!(
        argv.windows(2).any(|w| w == ["-o", "ConnectTimeout=15"]),
        "ConnectTimeout should be passed to ssh: {argv:?}"
    );
    assert!(
        argv.windows(2).any(|w| w == ["-p", "2222"]),
        "-p should be passed to ssh: {argv:?}"
    );
    assert!(
        !logged.contains("RemoteCommand"),
        "RemoteCommand must not reach the bootstrap ssh: {argv:?}"
    );
    assert!(
        !argv.contains(&"-T") && !argv.contains(&"-D"),
        "-T/-D are handled by noissh, not ssh: {argv:?}"
    );

    let _ = fs::remove_dir_all(&dir);
}
