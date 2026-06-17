//! noissh — the noissh client.
//!
//! Modes:
//!   noissh [--port N] [user@]host
//!       Direct connect to a standalone noisshd (known_hosts TOFU pinning).
//!   noissh --ssh [user@]host [--server-cmd noisshd] [-- <ssh args>...]
//!       mosh-style: bootstrap the server over SSH, then run over Noise/UDP.

use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::os::fd::AsRawFd;
use std::process::exit;
use std::time::Duration;

use auth::{KnownHosts, PublicKey, Tofu};
use noissh::client::Client;
use noissh::config::{config_dir, load_known_hosts, load_or_generate_keypair, save_known_hosts};
use noissh::tty::{terminal_size, RawMode, Renderer};
use noissh::{ssh, RuntimeError};
use predict::DisplayMode;

fn main() {
    if let Err(e) = run() {
        eprintln!("\r\nnoissh: {e}");
        exit(1);
    }
}

struct Args {
    ssh: bool,
    port: u16,
    target: Option<String>,
    server_cmd: String,
    ssh_args: Vec<String>,
}

fn parse_args() -> Args {
    let mut a = Args {
        ssh: false,
        port: 51820,
        target: None,
        server_cmd: "noisshd".to_string(),
        ssh_args: Vec::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--ssh" => a.ssh = true,
            "--port" => {
                if let Some(p) = it.next().and_then(|s| s.parse().ok()) {
                    a.port = p;
                }
            }
            "--server-cmd" => {
                if let Some(c) = it.next() {
                    a.server_cmd = c;
                }
            }
            "--" => a.ssh_args = it.by_ref().collect(),
            other => {
                if a.target.is_none() {
                    a.target = Some(other.to_string());
                }
            }
        }
    }
    a
}

fn run() -> Result<(), RuntimeError> {
    let args = parse_args();
    let target = args.target.clone().ok_or(RuntimeError::SshBootstrap)?;

    let dir = config_dir();
    let keypair = load_or_generate_keypair(&dir.join("id"))?;
    let kh_path = dir.join("known_hosts");
    let mut known = load_known_hosts(&kh_path)?;

    let (cols, rows) = terminal_size();

    let (server_addr, host_label) = if args.ssh {
        // mosh-style bootstrap over SSH.
        let boot = ssh::bootstrap(&target, &[args.server_cmd.clone()], &keypair.public, &args.ssh_args)?;
        // The server key arrived over the authenticated SSH channel: pin it
        // directly under the host:port label so the UDP handshake validates.
        let label = format!("{}:{}", ssh::host_of(&target), boot.server_addr.port());
        pin_key(&mut known, &label, &boot.server_pubkey)?;
        save_known_hosts(&kh_path, &known)?;
        (boot.server_addr, label)
    } else {
        let host = ssh::host_of(&target).to_string();
        let addr = (host.as_str(), args.port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
            .ok_or(RuntimeError::SshBootstrap)?;
        (addr, format!("{host}:{}", args.port))
    };

    let mut client = Client::connect(
        &keypair,
        known,
        host_label,
        server_addr,
        rows,
        cols,
        DisplayMode::Adaptive,
    )?;

    // Persist any newly-pinned host key (direct-mode TOFU).
    if client.core().known_hosts_dirty() {
        save_known_hosts(&kh_path, client.core().known_hosts())?;
    }

    interactive_loop(&mut client)
}

/// Pin a key under a label, hard-failing on mismatch (used after SSH bootstrap).
fn pin_key(known: &mut KnownHosts, label: &str, pubkey: &[u8]) -> Result<(), RuntimeError> {
    let key = PublicKey::from_bytes(pubkey)?;
    match known.check_or_add(label, &key) {
        Tofu::Mismatch => Err(RuntimeError::HostKeyMismatch(label.to_string())),
        _ => Ok(()),
    }
}

fn interactive_loop(client: &mut Client) -> Result<(), RuntimeError> {
    let _raw = RawMode::enable()?;
    let mut renderer = Renderer::new();

    let stdin = std::io::stdin();
    set_nonblocking(stdin.as_raw_fd());

    let mut stdout = std::io::stdout();
    stdout.write_all(b"\x1b[2J\x1b[H")?; // clear screen
    stdout.flush()?;

    let mut last_size = terminal_size();
    let mut inbuf = [0u8; 4096];

    loop {
        client.pump_once()?;

        // Forward local keystrokes.
        match stdin.lock().read(&mut inbuf) {
            Ok(0) => {}
            Ok(n) => client.core_mut().type_input(&inbuf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {}
        }

        // Detect local resize.
        let size = terminal_size();
        if size != last_size {
            last_size = size;
            client.core_mut().resize(size.0, size.1);
            renderer.invalidate();
        }

        // Render the predicted overlay.
        let overlay = client.core().overlay();
        renderer.paint(&overlay, &mut stdout)?;

        if let Some(status) = client.core().exit_status() {
            stdout.write_all(b"\x1b[?25h\r\n")?;
            stdout.flush()?;
            drop(_raw);
            exit(status);
        }

        std::thread::sleep(Duration::from_millis(8));
    }
}

fn set_nonblocking(fd: i32) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}
