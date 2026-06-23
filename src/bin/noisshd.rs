#![forbid(unsafe_code)]
//! noisshd — the noissh server daemon.
//!
//! Modes:
//!   noisshd [--listen ADDR] [--key PATH] [--authorized-keys PATH] [--command CMD ...]
//!       Standalone daemon: persistent key, persistent authorized_keys.
//!   noisshd --one-shot --authorize <b64pub> [--bind ADDR] [--command CMD ...]
//!       one-shot: ephemeral key, trust the one given client key, bind an
//!       ephemeral UDP port, print the connect line, detach, serve one session.

use std::net::SocketAddr;
use std::process::exit;
use std::time::{Duration, Instant};

use auth::{AuthorizedKeys, PublicKey};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use noissh::config::{config_dir, load_authorized_keys, load_or_generate_keypair};
use noissh::server::{Server, ServerCore};
use noissh::{RuntimeError, ssh};

fn main() {
    if let Err(e) = run() {
        eprintln!("noisshd: {e}");
        exit(1);
    }
}

struct Args {
    one_shot: bool,
    listen: Option<String>,
    bind: Option<String>,
    key: Option<String>,
    authorized_keys: Option<String>,
    authorize: Option<String>,
    command: Option<Vec<String>>,
    verbose: bool,
}

fn print_help() {
    println!(
        "noisshd {ver} — the noissh server daemon

Usage:
  noisshd [--listen ADDR] [--key PATH] [--authorized-keys PATH] [--command CMD ...]
  noisshd --one-shot --authorize <b64pub> [--bind ADDR] [--command CMD ...]

Modes:
  standalone (default)  persistent key + authorized_keys; serves many sessions.
  --one-shot            ephemeral key, trust one client key, serve one session,
                        then exit. Used by the client's SSH bootstrap.

Options:
  --listen ADDR         UDP listen address (default 0.0.0.0:51820)
  --bind ADDR           one-shot: UDP bind address (default 0.0.0.0:0)
  --key PATH            server keypair path (standalone)
  --authorized-keys P   authorized client keys path (standalone)
  --authorize B64       one-shot: the single client public key to trust
  --command CMD ...     run CMD instead of a login shell (rest of argv)
  -v, --verbose         log session lifecycle events
  -h, --help            print this help and exit
  -V, --version         print the version and exit

Docs: https://github.com/gedigi/noissh#documentation",
        ver = env!("CARGO_PKG_VERSION"),
    );
}

fn parse_args() -> Args {
    let mut a = Args {
        one_shot: false,
        listen: None,
        bind: None,
        key: None,
        authorized_keys: None,
        authorize: None,
        command: None,
        verbose: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                exit(0);
            }
            "-V" | "--version" => {
                println!("noisshd {}", env!("CARGO_PKG_VERSION"));
                exit(0);
            }
            "--one-shot" => a.one_shot = true,
            "-v" | "--verbose" => a.verbose = true,
            "--listen" => a.listen = it.next(),
            "--bind" => a.bind = it.next(),
            "--key" => a.key = it.next(),
            "--authorized-keys" => a.authorized_keys = it.next(),
            "--authorize" => a.authorize = it.next(),
            "--command" => {
                // Remaining args form the command to run instead of a shell.
                a.command = Some(it.by_ref().collect());
            }
            other => eprintln!("noisshd: ignoring unknown arg {other:?}"),
        }
    }
    a
}

fn run() -> Result<(), RuntimeError> {
    let args = parse_args();
    if args.one_shot {
        run_one_shot(args)
    } else {
        run_standalone(args)
    }
}

fn run_standalone(args: Args) -> Result<(), RuntimeError> {
    let dir = config_dir();
    let key_path = args
        .key
        .map(Into::into)
        .unwrap_or_else(|| dir.join("noisshd_key"));
    let ak_path = args
        .authorized_keys
        .map(Into::into)
        .unwrap_or_else(|| dir.join("authorized_keys"));

    let keypair = load_or_generate_keypair(&key_path)?;
    let authorized = load_authorized_keys(&ak_path)?;

    let listen: SocketAddr = args
        .listen
        .as_deref()
        .unwrap_or("0.0.0.0:51820")
        .parse()
        .map_err(|_| RuntimeError::BadKeyFile)?;

    let mut core = ServerCore::local(keypair.clone(), authorized);
    if let Some(cmd) = args.command {
        core = core.with_command(cmd);
    }
    let mut server = Server::bind(listen, core)?;
    eprintln!(
        "noisshd listening on {} (pubkey {})",
        server.local_addr()?,
        STANDARD.encode(&keypair.public)
    );
    if args.verbose {
        serve_verbose(&mut server);
    } else {
        server.run();
    }
    Ok(())
}

/// Standalone serve loop with session-lifecycle logging (`-v`). Logs whenever
/// the active-session count changes and on a fatal socket error.
fn serve_verbose(server: &mut Server) {
    let mut active = server.core().session_count();
    eprintln!("noisshd: verbose logging enabled");
    loop {
        if !server.poll_once() {
            eprintln!("noisshd: fatal socket error; stopping");
            break;
        }
        let now = server.core().session_count();
        if now != active {
            if now > active {
                eprintln!("noisshd: session established ({now} active)");
            } else {
                eprintln!("noisshd: session ended ({now} active)");
            }
            active = now;
        }
    }
}

fn run_one_shot(args: Args) -> Result<(), RuntimeError> {
    // Ephemeral key; trust only the client key passed over the SSH channel.
    let keypair = noise_core::generate_keypair()?;
    let authorize_b64 = args.authorize.clone().ok_or(RuntimeError::SshBootstrap)?;
    // Validate the client key up front (fail fast on a bad value).
    PublicKey::from_bytes(
        &STANDARD
            .decode(&authorize_b64)
            .map_err(|_| RuntimeError::BadKeyFile)?,
    )?;

    let bind: SocketAddr = args
        .bind
        .as_deref()
        .unwrap_or("0.0.0.0:0")
        .parse()
        .map_err(|_| RuntimeError::BadKeyFile)?;

    // Build a fresh core (Server::bind consumes it, so we need one per attempt).
    let make_core = || -> Result<ServerCore, RuntimeError> {
        let mut authorized = AuthorizedKeys::new();
        let raw = STANDARD
            .decode(&authorize_b64)
            .map_err(|_| RuntimeError::BadKeyFile)?;
        authorized.add(PublicKey::from_bytes(&raw)?, "ssh-bootstrap");
        let mut core = ServerCore::local(keypair.clone(), authorized);
        if let Some(cmd) = &args.command {
            core = core.with_command(cmd.clone());
        }
        Ok(core)
    };

    // Bind the requested port; if it's already taken (e.g. a concurrent session),
    // fall back to an ephemeral port so the bootstrap still succeeds. The actual
    // port is reported in the connect line, so the client always reaches us.
    let mut server = match Server::bind(bind, make_core()?) {
        Ok(s) => s,
        Err(_) if bind.port() != 0 => {
            let eph: SocketAddr = "0.0.0.0:0".parse().unwrap();
            Server::bind(eph, make_core()?)?
        }
        Err(e) => return Err(e),
    };
    let port = server.local_addr()?.port();

    // Hand the port + pubkey back over SSH, then detach so SSH can return.
    println!("{}", ssh::connect_line(port, &keypair.public));
    use std::io::Write;
    std::io::stdout().flush().ok();
    ssh::daemonize()?;

    // Serve: exit if no client connects within the grace period, or once the
    // session's shell has exited.
    let grace = Duration::from_secs(60);
    let start = Instant::now();
    loop {
        if !server.poll_once() {
            break;
        }
        if server.core().all_done() {
            for _ in 0..20 {
                server.poll_once(); // flush the exit notice
            }
            break;
        }
        if server.core().session_count() == 0 && start.elapsed() > grace {
            break; // nobody connected
        }
    }
    Ok(())
}
