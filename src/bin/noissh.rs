#![forbid(unsafe_code)]
//! noissh — the noissh client.
//!
//! Modes:
//!   noissh [--port N] [user@]host
//!       Direct connect to a standalone noisshd (known_hosts TOFU pinning).
//!   noissh --ssh [user@]host [--server-cmd noisshd] [-- <ssh args>...]
//!       bootstrap the server over SSH, then run the session over Noise/UDP.

use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::process::exit;
use std::time::Duration;

use auth::{KnownHosts, PublicKey, Tofu};
use noissh::client::Client;
use noissh::config::{config_dir, load_known_hosts, load_or_generate_keypair, save_known_hosts};
use noissh::tty::{RawMode, Renderer, terminal_size};
use noissh::{RuntimeError, ssh};
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
    /// Local port forwards: (local_port, "host:port").
    local_forwards: Vec<(u16, String)>,
    /// Remote port forwards: (remote_port, "host:port").
    remote_forwards: Vec<(u16, String)>,
}

/// Parse a `-L` spec `LPORT:HOST:PORT` into (local_port, "HOST:PORT").
fn parse_forward(s: &str) -> Option<(u16, String)> {
    let (lport, target) = s.split_once(':')?;
    let port: u16 = lport.parse().ok()?;
    if target.is_empty() {
        return None;
    }
    Some((port, target.to_string()))
}

fn parse_args() -> Args {
    let mut a = Args {
        ssh: false,
        port: 51820,
        target: None,
        server_cmd: "noisshd".to_string(),
        ssh_args: Vec::new(),
        local_forwards: Vec::new(),
        remote_forwards: Vec::new(),
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
            "-L" => {
                if let Some(spec) = it.next().as_deref().and_then(parse_forward) {
                    a.local_forwards.push(spec);
                } else {
                    eprintln!("noissh: ignoring malformed -L spec (want LPORT:HOST:PORT)");
                }
            }
            "-R" => {
                if let Some(spec) = it.next().as_deref().and_then(parse_forward) {
                    a.remote_forwards.push(spec);
                } else {
                    eprintln!("noissh: ignoring malformed -R spec (want RPORT:HOST:PORT)");
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
        // Bootstrap the server over SSH.
        let boot = ssh::bootstrap(
            &target,
            std::slice::from_ref(&args.server_cmd),
            &keypair.public,
            &args.ssh_args,
        )?;
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

    // Forward-only when `-L`/`-R` is given (no interactive shell), like `ssh -N`.
    let forward_only = !args.local_forwards.is_empty() || !args.remote_forwards.is_empty();
    let mut client = Client::connect_with(
        &keypair,
        known,
        host_label,
        server_addr,
        rows,
        cols,
        DisplayMode::Adaptive,
        !forward_only,
    )?;

    // Persist any newly-pinned host key (direct-mode TOFU).
    if client.core().known_hosts_dirty() {
        save_known_hosts(&kh_path, client.core().known_hosts())?;
    }

    if forward_only {
        client.run_forwards(&args.local_forwards, &args.remote_forwards)
    } else {
        interactive_loop(&mut client)
    }
}

/// Pin a key under a label, hard-failing on mismatch (used after SSH bootstrap).
fn pin_key(known: &mut KnownHosts, label: &str, pubkey: &[u8]) -> Result<(), RuntimeError> {
    let key = PublicKey::from_bytes(pubkey)?;
    match known.check_or_add(label, &key) {
        Tofu::Mismatch => Err(RuntimeError::HostKeyMismatch(label.to_string())),
        _ => Ok(()),
    }
}

/// How often to send a keepalive while otherwise idle.
const KEEPALIVE: Duration = Duration::from_secs(3);
/// Poll wakeup while there is unacked data to (re)transmit.
const ACTIVE_POLL: Duration = Duration::from_millis(40);

fn interactive_loop(client: &mut Client) -> Result<(), RuntimeError> {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use std::os::fd::AsFd;
    use std::time::Instant;

    let _raw = RawMode::enable()?;
    let mut renderer = Renderer::new();

    // The loop waits via poll(); make the UDP socket non-blocking so draining
    // recv returns WouldBlock instead of blocking on each retransmit.
    client.socket().set_nonblocking(true).ok();

    let stdin = std::io::stdin();
    set_nonblocking(stdin.as_fd());

    let mut stdout = std::io::stdout();
    stdout.write_all(b"\x1b[2J\x1b[H")?; // clear screen
    stdout.flush()?;

    let mut last_size = terminal_size();
    let mut inbuf = [0u8; 4096];
    let mut next_keepalive = Instant::now() + KEEPALIVE;

    loop {
        // Wait for the socket or stdin to be ready, or a timer to fire. This is
        // event-driven: idle sessions wake only to keepalive, not in a busy loop.
        let timeout = if client.core().has_outgoing() {
            ACTIVE_POLL
        } else {
            next_keepalive
                .saturating_duration_since(Instant::now())
                .min(KEEPALIVE)
        };
        {
            let sock = client.socket().as_fd();
            let inp = stdin.as_fd();
            let mut fds = [
                PollFd::new(sock, PollFlags::POLLIN),
                PollFd::new(inp, PollFlags::POLLIN),
            ];
            let ms: u16 = timeout.as_millis().min(u16::MAX as u128) as u16;
            let _ = poll(&mut fds, PollTimeout::from(ms));
        }

        // Network: drain everything ready.
        while client.recv_and_handle()? {}

        // Local keystrokes.
        loop {
            match stdin.lock().read(&mut inbuf) {
                Ok(0) => break,
                Ok(n) => client.core_mut().type_input(&inbuf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        // Local resize.
        let size = terminal_size();
        if size != last_size {
            last_size = size;
            client.core_mut().resize(size.0, size.1);
            renderer.invalidate();
        }

        client.flush()?;

        // Keepalive.
        if Instant::now() >= next_keepalive {
            client.send_keepalive()?;
            next_keepalive = Instant::now() + KEEPALIVE;
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
    }
}

fn set_nonblocking<Fd: std::os::fd::AsFd>(fd: Fd) {
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    if let Ok(cur) = fcntl(fd.as_fd(), FcntlArg::F_GETFL) {
        let mut flags = OFlag::from_bits_truncate(cur);
        flags.insert(OFlag::O_NONBLOCK);
        let _ = fcntl(fd.as_fd(), FcntlArg::F_SETFL(flags));
    }
}
