//! PTY allocation and login-shell launching.
//!
//! Built on the safe [`pty_process`] crate (which encapsulates the PTY/fork/exec
//! and controlling-terminal setup), so this crate contains no `unsafe` code.
//!
//! The portable [`LocalLogin`] backend allocates a real PTY and execs the login
//! shell. It runs as the current user by default; if a target user is given it
//! drops to that user's uid/gid before exec (requires root). For full multi-user
//! deployments use the mosh-style SSH bootstrap, where the server is already
//! launched as the authenticated user by SSH — so no in-process setuid (and its
//! supplementary-group subtleties) is involved.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::process::Child;

use pty_process::Size;
use pty_process::blocking::{Command, Pty};
use thiserror::Error;

pub mod login;
pub use login::{LocalLogin, LoginSession};

#[derive(Debug, Error)]
pub enum PtyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("pty: {0}")]
    Pty(String),
    #[error("operation would block")]
    WouldBlock,
    #[error("unknown user {0:?}")]
    UnknownUser(String),
    #[error("system error: {0}")]
    Nix(#[from] nix::errno::Errno),
}

impl From<pty_process::Error> for PtyError {
    fn from(e: pty_process::Error) -> Self {
        PtyError::Pty(e.to_string())
    }
}

/// A request to start a login session.
#[derive(Debug, Clone)]
pub struct SpawnRequest {
    /// Target user. `None` = current user (no privilege change). When set, the
    /// child drops to that user's uid/gid before exec (requires root).
    pub user: Option<String>,
    /// Command + args to exec. `None` = the target user's login shell.
    pub command: Option<Vec<String>>,
    /// Extra environment variables to set (TERM is set from `term`).
    pub env: Vec<(String, String)>,
    pub term: String,
    pub rows: u16,
    pub cols: u16,
}

impl Default for SpawnRequest {
    fn default() -> Self {
        SpawnRequest {
            user: None,
            command: None,
            env: Vec::new(),
            term: "xterm-256color".to_string(),
            rows: 24,
            cols: 80,
        }
    }
}

/// A running PTY-backed child process.
pub struct PtyHandle {
    pty: Pty,
    child: Child,
    status: Option<i32>,
}

impl PtyHandle {
    /// Make the master end non-blocking (for event-loop integration).
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), PtyError> {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        use std::os::fd::AsFd;
        let cur = fcntl(self.pty.as_fd(), FcntlArg::F_GETFL)?;
        let mut flags = OFlag::from_bits_truncate(cur);
        flags.set(OFlag::O_NONBLOCK, nonblocking);
        fcntl(self.pty.as_fd(), FcntlArg::F_SETFL(flags))?;
        Ok(())
    }

    /// Read shell output. Returns `Ok(0)` at EOF (child closed the PTY) and
    /// `Err(WouldBlock)` when non-blocking and no data is ready.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, PtyError> {
        loop {
            match (&self.pty).read(buf) {
                Ok(n) => return Ok(n),
                // Interrupted by a signal (e.g. SIGWINCH): retry, don't treat as EOF.
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(PtyError::WouldBlock);
                }
                // EIO and other read errors on a PTY master mean the slave is gone.
                Err(_) => return Ok(0),
            }
        }
    }

    /// Write bytes (e.g. keystrokes) to the shell.
    pub fn write(&self, buf: &[u8]) -> Result<usize, PtyError> {
        let mut master = &self.pty;
        Ok(master.write(buf)?)
    }

    /// Propagate a window resize to the PTY (sends SIGWINCH to the shell).
    pub fn set_winsize(&self, rows: u16, cols: u16) -> Result<(), PtyError> {
        Ok(self.pty.resize(Size::new(rows, cols))?)
    }

    /// Non-blocking check for child exit; returns the exit status if exited.
    pub fn try_wait(&mut self) -> Result<Option<i32>, PtyError> {
        if let Some(s) = self.status {
            return Ok(Some(s));
        }
        match self.child.try_wait()? {
            Some(es) => {
                let code = status_code(es);
                self.status = Some(code);
                Ok(Some(code))
            }
            None => Ok(None),
        }
    }

    /// Block until the child exits, returning its status.
    pub fn wait(&mut self) -> Result<i32, PtyError> {
        if let Some(s) = self.status {
            return Ok(s);
        }
        let es = self.child.wait()?;
        let code = status_code(es);
        self.status = Some(code);
        Ok(code)
    }

    /// Terminate the child.
    pub fn kill(&mut self) -> Result<(), PtyError> {
        let _ = self.child.kill();
        Ok(())
    }
}

impl Drop for PtyHandle {
    fn drop(&mut self) {
        if self.status.is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Map an `ExitStatus` to a shell-style integer code (128 + signal if killed).
fn status_code(es: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    es.code().unwrap_or_else(|| 128 + es.signal().unwrap_or(0))
}

/// Resolve the request to a command + env and spawn it under a fresh PTY.
pub(crate) fn spawn(req: &SpawnRequest) -> Result<PtyHandle, PtyError> {
    use nix::unistd::{User, getuid};

    let target = match &req.user {
        Some(name) => User::from_name(name)?.ok_or_else(|| PtyError::UnknownUser(name.clone()))?,
        None => {
            User::from_uid(getuid())?.ok_or_else(|| PtyError::UnknownUser(getuid().to_string()))?
        }
    };

    let shell =
        std::env::var("SHELL").unwrap_or_else(|_| target.shell.to_string_lossy().into_owned());

    let (pty, pts) = pty_process::blocking::open()?;
    pty.resize(Size::new(req.rows, req.cols))?;

    let mut cmd = match &req.command {
        Some(c) if !c.is_empty() => {
            let mut b = Command::new(&c[0]);
            if c.len() > 1 {
                b = b.args(&c[1..]);
            }
            b
        }
        _ => {
            // Login shell convention: argv[0] = "-<basename>".
            let base = shell.rsplit('/').next().unwrap_or("sh");
            Command::new(&shell).arg0(format!("-{base}"))
        }
    };

    cmd = cmd
        .env("TERM", &req.term)
        .env("HOME", &target.dir)
        .env("USER", &target.name)
        .env("SHELL", &shell);
    for (k, v) in &req.env {
        cmd = cmd.env(k, v);
    }
    if req.user.is_some() {
        // Basic privilege drop (uid/gid). Requires root. Supplementary groups
        // are not initialised here; prefer the SSH-bootstrap model for full
        // multi-user fidelity.
        cmd = cmd.uid(target.uid.as_raw()).gid(target.gid.as_raw());
    }

    let child = cmd.spawn(pts)?;
    Ok(PtyHandle {
        pty,
        child,
        status: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_to_end(h: &mut PtyHandle) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match h.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(PtyError::WouldBlock) => continue,
                Err(_) => break,
            }
        }
        out
    }

    #[test]
    fn spawn_command_captures_output() {
        let login = LocalLogin;
        let req = SpawnRequest {
            command: Some(vec!["/bin/echo".into(), "hello-pty".into()]),
            ..Default::default()
        };
        let mut h = login.spawn(&req).unwrap();
        let out = read_to_end(&mut h);
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("hello-pty"), "got: {s:?}");
        assert_eq!(h.wait().unwrap(), 0);
    }

    #[test]
    fn exit_status_propagates() {
        let login = LocalLogin;
        let req = SpawnRequest {
            command: Some(vec!["/bin/sh".into(), "-c".into(), "exit 7".into()]),
            ..Default::default()
        };
        let mut h = login.spawn(&req).unwrap();
        let _ = read_to_end(&mut h);
        assert_eq!(h.wait().unwrap(), 7);
    }

    #[test]
    fn winsize_is_applied_to_pty() {
        let login = LocalLogin;
        let req = SpawnRequest {
            command: Some(vec!["/bin/sh".into(), "-c".into(), "stty size".into()]),
            rows: 30,
            cols: 100,
            ..Default::default()
        };
        let mut h = login.spawn(&req).unwrap();
        let out = read_to_end(&mut h);
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("30 100"), "stty size returned: {s:?}");
    }

    #[test]
    fn resize_after_spawn_updates_winsize() {
        let login = LocalLogin;
        let req = SpawnRequest {
            command: Some(vec![
                "/bin/sh".into(),
                "-c".into(),
                "sleep 0.3; stty size".into(),
            ]),
            rows: 24,
            cols: 80,
            ..Default::default()
        };
        let mut h = login.spawn(&req).unwrap();
        h.set_winsize(40, 120).unwrap();
        let out = read_to_end(&mut h);
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("40 120"), "after resize stty size: {s:?}");
    }

    #[test]
    fn interactive_shell_echoes_input() {
        let login = LocalLogin;
        let req = SpawnRequest {
            command: Some(vec!["/bin/sh".into()]),
            ..Default::default()
        };
        let mut h = login.spawn(&req).unwrap();
        h.write(b"echo round-trip-ok\n").unwrap();
        h.write(b"exit\n").unwrap();
        let out = read_to_end(&mut h);
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("round-trip-ok"), "shell output: {s:?}");
    }
}
