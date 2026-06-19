//! SSH bootstrap.
//!
//! `ssh` is used only to launch the remote server and hand back its UDP port +
//! ephemeral public key over the already-authenticated SSH channel; the actual
//! session then runs over the Noise/UDP transport. The SSH connection is not
//! kept open — the one-shot server detaches (daemonizes) and keeps serving
//! after `ssh` exits.

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

/// Outcome of a single bootstrap attempt.
enum Attempt {
    /// Parsed a connect line; the server is up.
    Connected(Bootstrap),
    /// The remote `noisshd` command was not found (likely not installed).
    NotFound,
    /// Some other failure (no connect line, but not a missing-command signal).
    Failed,
}

/// The `ssh` program, overridable via `$NOISSH_SSH` (tests / custom transports).
fn ssh_prog() -> String {
    std::env::var("NOISSH_SSH").unwrap_or_else(|_| "ssh".to_string())
}

/// Heuristic: did the remote command fail because it isn't installed? `ssh`
/// exits 127 when the remote command is not found; also match the shell's
/// "command not found" / "No such file" text as a fallback.
fn looks_like_missing_command(output: &std::process::Output) -> bool {
    if output.status.code() == Some(127) {
        return true;
    }
    let mut s = String::from_utf8_lossy(&output.stderr).to_lowercase();
    s.push_str(&String::from_utf8_lossy(&output.stdout).to_lowercase());
    // Match only the specific shell phrasings for a missing command, so a
    // working-but-erroring noisshd (whose output merely contains "not found")
    // doesn't trigger a spurious reinstall over it.
    s.contains("command not found")
        || s.contains(": not found") // POSIX sh: "noisshd: not found"
        || s.contains("no such file or directory")
}

/// Whether `remote_server_cmd` is the default (unconfigured) `noisshd` — we only
/// auto-install when the user hasn't pointed us at a custom server command.
fn is_default_server_cmd(remote_server_cmd: &[String]) -> bool {
    remote_server_cmd.len() == 1 && remote_server_cmd[0] == "noisshd"
}

/// Run one bootstrap attempt against `remote_server_cmd`.
fn attempt(
    target: &str,
    remote_server_cmd: &[String],
    client_pubkey: &[u8],
    extra_ssh_args: &[String],
    bind_port: Option<u16>,
) -> Result<Attempt, RuntimeError> {
    let mut cmd = Command::new(ssh_prog());
    cmd.args(extra_ssh_args);
    // `--` terminates ssh option parsing so a `target` starting with `-` can't
    // be smuggled in as an ssh flag (argument injection).
    cmd.arg("--");
    cmd.arg(target);
    for part in remote_server_cmd {
        cmd.arg(part);
    }
    cmd.arg("--one-shot");
    cmd.arg("--authorize");
    cmd.arg(STANDARD.encode(client_pubkey));
    // Pin the server's UDP port (so it can be opened in a firewall) instead of
    // the default ephemeral bind.
    if let Some(p) = bind_port {
        cmd.arg("--bind");
        cmd.arg(format!("0.0.0.0:{p}"));
    }

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Use the LAST matching line: the server prints the connect line as the very
    // last thing it does (after any SSH banner / MOTD), so this prevents a
    // server-controlled banner from injecting a forged connect line earlier in
    // the stream.
    if let Some((port, server_pubkey)) = stdout.lines().rev().find_map(parse_connect_line) {
        let host = host_of(target);
        let server_addr = (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or(RuntimeError::SshBootstrap)?;
        return Ok(Attempt::Connected(Bootstrap {
            server_addr,
            server_pubkey,
        }));
    }
    if looks_like_missing_command(&output) {
        Ok(Attempt::NotFound)
    } else {
        Ok(Attempt::Failed)
    }
}

/// Install `noisshd` on the remote over SSH by running the published installer
/// (which detects the remote platform, fetches the matching release binary, and
/// verifies its checksum). Installs into `~/.local/bin` so the retry can invoke
/// it by an absolute path regardless of the non-interactive `PATH`. Installer
/// output streams to the user's terminal.
fn install_remote(target: &str, extra_ssh_args: &[String]) -> Result<(), RuntimeError> {
    // Pin the installer to THIS client's released tag rather than a moving
    // branch, so an auto-install runs a versioned, reproducible script (the
    // installer itself then verifies the release binary's SHA-256 checksum).
    let installer = format!(
        "https://raw.githubusercontent.com/gedigi/noissh/v{}/install.sh",
        env!("CARGO_PKG_VERSION")
    );
    // One self-contained shell command: prefer curl, fall back to wget, error if
    // neither is available. `$HOME` is expanded by the remote shell.
    // Single-quote the URL in the remote command (defence in depth: the version
    // is a numeric compile-time constant, but quoting keeps it inert regardless).
    let remote = format!(
        "if command -v curl >/dev/null 2>&1; then \
           curl -fsSL '{installer}' | NOISSH_BIN_DIR=\"$HOME/.local/bin\" sh -s -- --yes; \
         elif command -v wget >/dev/null 2>&1; then \
           wget -qO- '{installer}' | NOISSH_BIN_DIR=\"$HOME/.local/bin\" sh -s -- --yes; \
         else echo 'noissh: remote has neither curl nor wget to install noisshd' >&2; exit 3; fi"
    );
    let mut cmd = Command::new(ssh_prog());
    cmd.args(extra_ssh_args);
    cmd.arg("--"); // terminate ssh option parsing (target may start with `-`)
    cmd.arg(target);
    cmd.arg(remote);
    // Inherit stdio so the user sees the installer's progress.
    let status = cmd.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(RuntimeError::SshBootstrap)
    }
}

/// The remote `noisshd` path to invoke after an auto-install. Overridable via
/// `$NOISSH_REMOTE_NOISSHD` (tests / custom install locations).
fn installed_noisshd_cmd() -> Vec<String> {
    vec![
        std::env::var("NOISSH_REMOTE_NOISSHD")
            .unwrap_or_else(|_| "$HOME/.local/bin/noisshd".to_string()),
    ]
}

/// Run `ssh <target> <remote_server_cmd> --one-shot --authorize <client_pub>`
/// and parse the connect line. `remote_server_cmd` is e.g. `["noisshd"]`.
///
/// When `auto_install` is set and the remote `noisshd` is missing (and the
/// server command is the default), install it over SSH and retry once.
pub fn bootstrap(
    target: &str,
    remote_server_cmd: &[String],
    client_pubkey: &[u8],
    extra_ssh_args: &[String],
    auto_install: bool,
    bind_port: Option<u16>,
) -> Result<Bootstrap, RuntimeError> {
    match attempt(
        target,
        remote_server_cmd,
        client_pubkey,
        extra_ssh_args,
        bind_port,
    )? {
        Attempt::Connected(b) => Ok(b),
        Attempt::NotFound if auto_install && is_default_server_cmd(remote_server_cmd) => {
            // It may already be installed at our known location but simply not on
            // the non-interactive PATH — try that before re-downloading.
            if let Attempt::Connected(b) = attempt(
                target,
                &installed_noisshd_cmd(),
                client_pubkey,
                extra_ssh_args,
                bind_port,
            )? {
                return Ok(b);
            }
            eprintln!(
                "noissh: noisshd is not installed on {}; installing it over SSH…",
                host_of(target)
            );
            install_remote(target, extra_ssh_args)?;
            match attempt(
                target,
                &installed_noisshd_cmd(),
                client_pubkey,
                extra_ssh_args,
                bind_port,
            )? {
                Attempt::Connected(b) => {
                    eprintln!("noissh: noisshd installed; connecting…");
                    Ok(b)
                }
                _ => Err(RuntimeError::SshBootstrap),
            }
        }
        _ => Err(RuntimeError::SshBootstrap),
    }
}

/// Detach from the controlling SSH session so the server survives `ssh`
/// returning. Uses the `daemonize` crate (double fork + `setsid` + stdio
/// redirected to `/dev/null`). Call AFTER the
/// connect line has been printed and flushed.
pub fn daemonize() -> Result<(), RuntimeError> {
    daemonize::Daemonize::new()
        .working_directory("/")
        .start()
        .map_err(|e| RuntimeError::Io(std::io::Error::other(e.to_string())))
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
    fn default_server_cmd_detection() {
        assert!(is_default_server_cmd(&["noisshd".to_string()]));
        assert!(!is_default_server_cmd(&["/opt/noisshd".to_string()]));
        assert!(!is_default_server_cmd(&[
            "noisshd".to_string(),
            "--x".to_string()
        ]));
        assert!(!is_default_server_cmd(&[]));
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
