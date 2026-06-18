//! mosh-style SSH bootstrap.
//!
//! `ssh` is used only to launch the remote server and hand back its UDP port +
//! ephemeral public key over the already-authenticated SSH channel; the actual
//! session then runs over the Noise/UDP transport. The SSH connection is not
//! kept open — the one-shot server detaches (daemonizes) and survives it,
//! exactly like `mosh-server`.

use std::net::{SocketAddr, ToSocketAddrs};
use std::process::Command;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::RuntimeError;

/// The line the one-shot server prints on stdout for the client to parse.
pub const CONNECT_PREFIX: &str = "NOISSH CONNECT";

/// Format the connect line: `NOISSH CONNECT <port> <base64 server pubkey>`.
pub fn connect_line(port: u16, server_pubkey: &[u8]) -> String {
    format!("{CONNECT_PREFIX} {port} {}", STANDARD.encode(server_pubkey))
}

/// Parse a connect line, returning (udp_port, server_pubkey).
pub fn parse_connect_line(line: &str) -> Option<(u16, Vec<u8>)> {
    let mut it = line.split_whitespace();
    if it.next()? != "NOISSH" || it.next()? != "CONNECT" {
        return None;
    }
    let port: u16 = it.next()?.parse().ok()?;
    let pubkey = STANDARD.decode(it.next()?).ok()?;
    if pubkey.len() != 32 {
        return None;
    }
    Some((port, pubkey))
}

/// Split a `[user@]host` target into its host part for address resolution.
pub fn host_of(target: &str) -> &str {
    match target.rsplit_once('@') {
        Some((_user, host)) => host,
        None => target,
    }
}

/// Result of the SSH bootstrap: where to send UDP and the server's pinned key.
pub struct Bootstrap {
    pub server_addr: SocketAddr,
    pub server_pubkey: Vec<u8>,
}

/// Run `ssh <target> <remote_server_cmd> --one-shot --authorize <client_pub>`
/// and parse the connect line. `remote_server_cmd` is e.g. `["noisshd"]`.
pub fn bootstrap(
    target: &str,
    remote_server_cmd: &[String],
    client_pubkey: &[u8],
    extra_ssh_args: &[String],
) -> Result<Bootstrap, RuntimeError> {
    // The ssh program is overridable via $NOISSH_SSH (used by tests and for
    // custom transports).
    let ssh_prog = std::env::var("NOISSH_SSH").unwrap_or_else(|_| "ssh".to_string());
    let mut cmd = Command::new(ssh_prog);
    cmd.args(extra_ssh_args);
    cmd.arg(target);
    for part in remote_server_cmd {
        cmd.arg(part);
    }
    cmd.arg("--one-shot");
    cmd.arg("--authorize");
    cmd.arg(STANDARD.encode(client_pubkey));

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Use the LAST matching line: the server prints the connect line as the very
    // last thing it does (after any SSH banner / MOTD), so this prevents a
    // server-controlled banner from injecting a forged connect line earlier in
    // the stream.
    let (port, server_pubkey) = stdout
        .lines()
        .rev()
        .find_map(parse_connect_line)
        .ok_or(RuntimeError::SshBootstrap)?;

    // Resolve the SSH host to a UDP socket address on the negotiated port.
    let host = host_of(target);
    let server_addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or(RuntimeError::SshBootstrap)?;

    Ok(Bootstrap {
        server_addr,
        server_pubkey,
    })
}

/// Detach from the controlling SSH session via a double fork: after `setsid`
/// the first child is a session leader (and could reacquire a controlling
/// terminal when it later opens a PTY); a second fork yields a process that is
/// not a session leader, the standard daemon pattern. The original and the
/// intermediate parent exit so `ssh` returns; the grandchild keeps serving.
/// Call AFTER the connect line has been printed and flushed.
pub fn daemonize() -> Result<(), RuntimeError> {
    use nix::unistd::{ForkResult, close, dup2_stderr, dup2_stdin, dup2_stdout, fork, setsid};
    // First fork + setsid: detach from the controlling terminal.
    match unsafe { fork() }.map_err(errno)? {
        ForkResult::Parent { .. } => std::process::exit(0),
        ForkResult::Child => {}
    }
    setsid().map_err(errno)?;
    // Second fork: ensure we are not a session leader.
    match unsafe { fork() }.map_err(errno)? {
        ForkResult::Parent { .. } => std::process::exit(0),
        ForkResult::Child => {}
    }
    // Redirect stdio to /dev/null so the SSH pipe is fully released.
    if let Ok(devnull) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
    {
        let _ = dup2_stdin(&devnull);
        let _ = dup2_stdout(&devnull);
        let _ = dup2_stderr(&devnull);
        use std::os::fd::IntoRawFd;
        let raw = devnull.into_raw_fd();
        if raw > 2 {
            use std::os::fd::FromRawFd;
            let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
            let _ = close(owned);
        }
    }
    Ok(())
}

fn errno(e: nix::errno::Errno) -> RuntimeError {
    RuntimeError::Io(std::io::Error::from_raw_os_error(e as i32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_line_roundtrips() {
        let key = [9u8; 32];
        let line = connect_line(60001, &key);
        let (port, pk) = parse_connect_line(&line).unwrap();
        assert_eq!(port, 60001);
        assert_eq!(pk, key);
    }

    #[test]
    fn parse_ignores_noise_lines() {
        assert!(parse_connect_line("some banner text").is_none());
        assert!(parse_connect_line("NOISSH CONNECT notaport AAAA").is_none());
    }

    #[test]
    fn parse_rejects_wrong_key_length() {
        let line = format!("{CONNECT_PREFIX} 5 {}", STANDARD.encode([1u8; 16]));
        assert!(parse_connect_line(&line).is_none());
    }

    #[test]
    fn host_extraction() {
        assert_eq!(host_of("user@example.com"), "example.com");
        assert_eq!(host_of("example.com"), "example.com");
    }

    #[test]
    fn finds_connect_line_among_others() {
        let blob = "Warning: something\nNOISSH CONNECT 7000 ".to_string()
            + &STANDARD.encode([2u8; 32])
            + "\nbye";
        let (port, pk) = blob.lines().find_map(parse_connect_line).unwrap();
        assert_eq!(port, 7000);
        assert_eq!(pk, vec![2u8; 32]);
    }
}
