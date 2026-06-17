//! noisshd — the noissh server daemon.
//!
//! Modes:
//!   noisshd [--listen ADDR] [--key PATH] [--authorized-keys PATH] [--command CMD ...]
//!       Standalone daemon: persistent key, persistent authorized_keys.
//!   noisshd --one-shot --authorize <b64pub> [--bind ADDR] [--command CMD ...]
//!       mosh-style: ephemeral key, trust the one given client key, bind an
//!       ephemeral UDP port, print the connect line, detach, serve one session.

use std::net::SocketAddr;
use std::process::exit;
use std::time::{Duration, Instant};

use auth::{AuthorizedKeys, PublicKey};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use noissh::config::{config_dir, load_authorized_keys, load_or_generate_keypair};
use noissh::server::{Server, ServerCore};
use noissh::{ssh, RuntimeError};

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
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--one-shot" => a.one_shot = true,
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
    let key_path = args.key.map(Into::into).unwrap_or_else(|| dir.join("noisshd_key"));
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
    server.run();
    Ok(())
}

fn run_one_shot(args: Args) -> Result<(), RuntimeError> {
    // Ephemeral key; trust only the client key passed over the SSH channel.
    let keypair = noise_core::generate_keypair()?;
    let mut authorized = AuthorizedKeys::new();
    if let Some(b64) = &args.authorize {
        let raw = STANDARD.decode(b64).map_err(|_| RuntimeError::BadKeyFile)?;
        let key = PublicKey::from_bytes(&raw)?;
        authorized.add(key, "ssh-bootstrap");
    } else {
        return Err(RuntimeError::SshBootstrap);
    }

    let bind: SocketAddr = args
        .bind
        .as_deref()
        .unwrap_or("0.0.0.0:0")
        .parse()
        .map_err(|_| RuntimeError::BadKeyFile)?;

    let mut core = ServerCore::local(keypair.clone(), authorized);
    if let Some(cmd) = args.command {
        core = core.with_command(cmd);
    }
    let mut server = Server::bind(bind, core)?;
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
