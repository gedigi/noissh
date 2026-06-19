#![forbid(unsafe_code)]
//! noissh — the noissh client.
//!
//! Connecting:
//!   noissh [user@]host
//!       Try a direct UDP session to a standing noisshd (known_hosts TOFU); if
//!       nothing answers, automatically fall back to the SSH bootstrap below.
//!   noissh --ssh [user@]host [--server-cmd noisshd] [-- <ssh args>...]
//!       Force the SSH bootstrap: launch (and, if missing, install) noisshd over
//!       SSH, then run the session over Noise/UDP.
//!   noissh --direct [--port N] [user@]host
//!       Direct only — never fall back to SSH.

use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::process::exit;
use std::time::Duration;

use auth::{KnownHosts, PublicKey};
use noissh::client::Client;
use noissh::config::{config_dir, load_known_hosts, load_or_generate_keypair, save_known_hosts};
use noissh::tty::{RawMode, Renderer, TtyWriter, terminal_size};
use noissh::{RuntimeError, ssh};
use predict::DisplayMode;
use proto::XferRequest;

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
    /// Dynamic (SOCKS) forwards: (bind_addr, port).
    dynamic_forwards: Vec<(String, u16)>,
    /// A one-shot file transfer: (request, local path). Mutually exclusive with
    /// an interactive shell and port forwarding.
    transfer: Option<(proto::XferRequest, String)>,
    /// Forward the local SSH agent (`-A`).
    forward_agent: bool,
    /// Disable auto-installing noisshd on the remote during `--ssh` bootstrap.
    no_install: bool,
    /// Run a non-interactive remote command instead of an interactive shell.
    exec: Option<String>,
    /// Force a direct UDP connection only (never fall back to the SSH bootstrap).
    direct: bool,
    /// Pin the bootstrapped server's UDP port (so it can be opened in a firewall)
    /// instead of an ephemeral one.
    server_port: Option<u16>,
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

/// Parse a `-D` spec `[BIND:]PORT` into (bind_addr, port). Defaults to loopback.
fn parse_dynamic(s: &str) -> Option<(String, u16)> {
    match s.rsplit_once(':') {
        Some((bind, port)) if !bind.is_empty() => Some((bind.to_string(), port.parse().ok()?)),
        // ":1080" (empty bind) or a bare port → bind loopback.
        Some((_, port)) => Some(("127.0.0.1".to_string(), port.parse().ok()?)),
        None => Some(("127.0.0.1".to_string(), s.parse().ok()?)),
    }
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
        dynamic_forwards: Vec::new(),
        transfer: None,
        forward_agent: false,
        no_install: false,
        exec: None,
        direct: false,
        server_port: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--ssh" => a.ssh = true,
            "--direct" => a.direct = true,
            "--no-install" => a.no_install = true,
            "--exec" => {
                if let Some(c) = it.next() {
                    a.exec = Some(c);
                } else {
                    eprintln!("noissh: --exec wants a command string");
                }
            }
            "-A" | "--forward-agent" => a.forward_agent = true,
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
            "--server-port" => {
                if let Some(p) = it.next().and_then(|s| s.parse().ok()) {
                    a.server_port = Some(p);
                } else {
                    eprintln!("noissh: --server-port wants a port number");
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
            "-D" => {
                if let Some(spec) = it.next().as_deref().and_then(parse_dynamic) {
                    a.dynamic_forwards.push(spec);
                } else {
                    eprintln!("noissh: ignoring malformed -D spec (want [BIND:]PORT)");
                }
            }
            "--put" => match it.next().as_deref().and_then(|s| s.split_once(':')) {
                Some((local, remote)) if !local.is_empty() && !remote.is_empty() => {
                    let size = std::fs::metadata(local).map(|m| m.len()).unwrap_or(0);
                    a.transfer = Some((
                        XferRequest::Put {
                            path: remote.to_string(),
                            size,
                        },
                        local.to_string(),
                    ));
                }
                _ => eprintln!("noissh: --put wants LOCAL:REMOTE"),
            },
            "--get" => match it.next().as_deref().and_then(|s| s.split_once(':')) {
                Some((remote, local)) if !remote.is_empty() && !local.is_empty() => {
                    a.transfer = Some((
                        XferRequest::Get {
                            path: remote.to_string(),
                        },
                        local.to_string(),
                    ));
                }
                _ => eprintln!("noissh: --get wants REMOTE:LOCAL"),
            },
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

    let (cols, rows) = terminal_size();

    // No interactive shell for a one-shot transfer or when `-L`/`-R`/`-D` is
    // given (the latter behaves like `ssh -N`).
    let forward_only = !args.local_forwards.is_empty()
        || !args.remote_forwards.is_empty()
        || !args.dynamic_forwards.is_empty();
    let want_shell = !forward_only && args.transfer.is_none() && args.exec.is_none();
    // Agent forwarding only applies to an interactive shell; it needs a local
    // agent ($SSH_AUTH_SOCK) to bridge to.
    let agent_sock = if args.forward_agent && want_shell {
        match std::env::var("SSH_AUTH_SOCK") {
            Ok(s) if !s.is_empty() => Some(s),
            _ => {
                eprintln!("noissh: -A requested but SSH_AUTH_SOCK is not set; ignoring");
                None
            }
        }
    } else {
        None
    };

    // Connect: unless told otherwise, try a direct UDP session to a standing
    // noisshd first; if that doesn't answer (no daemon), fall back to the SSH
    // bootstrap automatically. `--ssh` forces bootstrap; `--direct` forbids it.
    let host = ssh::host_of(&target).to_string();
    let mut client = None;

    let label = format!("{host}:{}", args.port);
    let known = load_known_hosts(&kh_path)?;
    // Only attempt a direct connection when explicitly asked (`--direct`) or when
    // we already trust a standing server on this host:port (a known_hosts pin).
    // Otherwise go straight to the SSH bootstrap: the conventional port may be
    // hosting a transient, ephemeral-keyed one-shot from another session, and a
    // direct probe would either mis-pin its key or spuriously mismatch.
    let try_direct = args.direct || (!args.ssh && known.get(&label).is_some());

    if try_direct {
        if let Some(addr) = (host.as_str(), args.port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
        {
            match Client::connect_with(
                &keypair,
                known,
                label.clone(),
                addr,
                rows,
                cols,
                DisplayMode::Adaptive,
                want_shell,
                agent_sock.clone(),
                DIRECT_CONNECT_TIMEOUT,
            ) {
                Ok(c) => client = Some(c),
                // The known standing server didn't answer: fall back to SSH
                // (unless the user demanded a direct connection).
                Err(RuntimeError::Timeout) if !args.direct => {
                    eprintln!(
                        "noissh: the server on udp/{} didn't answer; bootstrapping over SSH…",
                        args.port
                    );
                }
                // A real failure (e.g. host-key mismatch) must not silently
                // trigger an SSH bootstrap that would re-pin a key.
                Err(e) => return Err(e),
            }
        } else if args.direct {
            return Err(RuntimeError::SshBootstrap); // can't resolve, can't fall back
        }
    }

    if client.is_none() {
        // SSH bootstrap: launch (and, if missing, install) noisshd over SSH.
        // Default the server's UDP port to the conventional one (`--port`, 51820)
        // rather than an ephemeral one, so a single firewall rule for that port
        // covers both direct and bootstrapped sessions. The server falls back to
        // an ephemeral port only if it's already taken.
        let server_port = args.server_port.unwrap_or(args.port);
        let boot = ssh::bootstrap(
            &target,
            std::slice::from_ref(&args.server_cmd),
            &keypair.public,
            &args.ssh_args,
            !args.no_install,
            Some(server_port),
        )?;
        // The server key arrived over the authenticated SSH channel. It's an
        // ephemeral one-shot key (different every connect), so trust it for THIS
        // session only — pin it in a fresh, in-memory known_hosts that is never
        // persisted. (Persisting it under a fixed --server-port label would look
        // like a host-key change on the next connect.) It still protects the UDP
        // handshake: an attacker who can't produce the SSH-delivered key can't
        // impersonate the server.
        let udp_port = boot.server_addr.port();
        let label = format!("{host}:{udp_port}");
        let mut boot_known = KnownHosts::new();
        boot_known.check_or_add(&label, &PublicKey::from_bytes(&boot.server_pubkey)?);
        client = Some(
            Client::connect_with(
                &keypair,
                boot_known,
                label,
                boot.server_addr,
                rows,
                cols,
                DisplayMode::Adaptive,
                want_shell,
                agent_sock,
                BOOTSTRAP_CONNECT_TIMEOUT,
            )
            .map_err(|e| {
                // The SSH side worked but the UDP session didn't establish — the
                // most common cause is the server's UDP port being unreachable
                // (firewall/NAT). Point the user at the fix.
                if matches!(e, RuntimeError::Timeout) {
                    eprintln!(
                        "noissh: connected over SSH but the UDP session to {host}:{udp_port} \
                         timed out — that UDP port is likely blocked by a firewall/NAT. \
                         Open it (or pick an open one with --server-port N) and retry."
                    );
                }
                e
            })?,
        );
    }

    let mut client = client.expect("a client was established");

    // Persist any newly-pinned host key (direct-mode TOFU).
    if client.core().known_hosts_dirty() {
        save_known_hosts(&kh_path, client.core().known_hosts())?;
    }

    if let Some(cmd) = args.exec {
        let code = client.run_exec(&cmd)?;
        exit(code);
    } else if let Some((req, local)) = args.transfer {
        client.run_transfer(&req, &local)?;
        eprintln!("noissh: transfer complete");
        Ok(())
    } else if forward_only {
        client.run_forwards(
            &args.local_forwards,
            &args.remote_forwards,
            &args.dynamic_forwards,
        )
    } else {
        interactive_loop(&mut client)
    }
}

/// How often to send a keepalive while otherwise idle.
const KEEPALIVE: Duration = Duration::from_secs(3);
/// Poll wakeup while there is unacked data to (re)transmit.
const ACTIVE_POLL: Duration = Duration::from_millis(40);
/// How long to probe for a direct (standing-daemon) UDP session before falling
/// back to the SSH bootstrap — short so the fallback is snappy.
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Handshake timeout for the SSH-bootstrapped session (the server is freshly
/// launched and known to be there).
const BOOTSTRAP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

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

    // Use a TTY writer that rides out EWOULDBLOCK: stdin and stdout share the
    // terminal file description, so making stdin non-blocking also makes stdout
    // non-blocking, and a large repaint would otherwise fail mid-write.
    let mut stdout = TtyWriter;
    stdout.write_all(b"\x1b[2J\x1b[H")?; // clear screen
    stdout.flush()?;

    let mut last_size = terminal_size();
    let mut inbuf = [0u8; 4096];
    let mut next_keepalive = Instant::now() + KEEPALIVE;

    // Restore the terminal if we're killed by a signal: register a flag for
    // SIGTERM/SIGINT/SIGHUP; the signal interrupts poll(), we observe the flag,
    // break out, and the RawMode guard's Drop runs (resetting termios). Without
    // this, an external `kill` would leave the terminal in raw mode.
    let signalled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    for sig in [
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGHUP,
    ] {
        let _ = signal_hook::flag::register(sig, std::sync::Arc::clone(&signalled));
    }

    loop {
        if signalled.load(std::sync::atomic::Ordering::Relaxed) {
            // Restore the cursor and terminal, then exit (128 + SIGTERM).
            let _ = stdout.write_all(b"\x1b[?25h\r\n");
            let _ = stdout.flush();
            drop(_raw);
            exit(143);
        }
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
            let mut fds = vec![
                PollFd::new(sock, PollFlags::POLLIN),
                PollFd::new(inp, PollFlags::POLLIN),
            ];
            // Also wait on any forwarded agent connections (no busy-spin).
            let agent_fds = client.agent_fds();
            for fd in &agent_fds {
                fds.push(PollFd::new(*fd, PollFlags::POLLIN));
            }
            let ms: u16 = timeout.as_millis().min(u16::MAX as u128) as u16;
            let _ = poll(&mut fds, PollTimeout::from(ms));
        }

        // Network: drain everything ready.
        while client.recv_and_handle()? {}

        // Service SSH agent forwarding (open/bridge/pump), if enabled.
        if client.agent_enabled() {
            client.pump_agent();
        }

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
