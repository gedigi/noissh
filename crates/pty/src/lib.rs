//! PTY allocation, login-shell launching, and (Linux) PAM/privilege separation.
//!
//! Two login backends share one [`LoginSession`] trait:
//!
//! - [`LocalLogin`] — portable: allocates a PTY and execs the login shell as
//!   the *current* user. This is the path exercised by the test-suite and by
//!   the local/dev daemon (no root needed).
//! - [`PrivsepLogin`] — the sshd-style flow: PAM `acct_mgmt`/`open_session`
//!   then `setgid`/`initgroups`/`setuid` to the target user before exec. PAM is
//!   Linux-only and gated behind `cfg(target_os = "linux")`; the privilege drop
//!   itself is portable but requires the daemon to run as root.

use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};

use nix::pty::{Winsize, openpty};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid};
use thiserror::Error;

pub mod login;
pub use login::{LocalLogin, LoginSession};

#[cfg(target_os = "linux")]
pub use login::PrivsepLogin;

#[derive(Debug, Error)]
pub enum PtyError {
    #[error("system error: {0}")]
    Sys(#[from] nix::errno::Errno),
    #[error("unknown user {0:?}")]
    UnknownUser(String),
    #[error("invalid command/env string (contains NUL)")]
    BadCString,
    #[error("pam: {0}")]
    Pam(String),
}

/// A request to start a login session.
#[derive(Debug, Clone)]
pub struct SpawnRequest {
    /// Target user. `None` = current user (no privilege change).
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

fn winsize(rows: u16, cols: u16) -> Winsize {
    Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

/// A running PTY-backed child process.
pub struct PtyHandle {
    master: OwnedFd,
    pid: Pid,
    status: Option<i32>,
}

impl PtyHandle {
    /// Raw master fd, e.g. to register with a poller.
    pub fn master_fd(&self) -> i32 {
        self.master.as_raw_fd()
    }

    /// Make the master end non-blocking (for event-loop integration).
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), PtyError> {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        let fd = self.master.as_raw_fd();
        let mut flags = OFlag::from_bits_truncate(fcntl(self.master_borrow(), FcntlArg::F_GETFL)?);
        flags.set(OFlag::O_NONBLOCK, nonblocking);
        fcntl(self.master_borrow(), FcntlArg::F_SETFL(flags))?;
        let _ = fd;
        Ok(())
    }

    fn master_borrow(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.master.as_fd()
    }

    /// Read shell output. Returns `Ok(0)` at EOF (child closed the PTY).
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, PtyError> {
        match nix::unistd::read(self.master_borrow(), buf) {
            Ok(n) => Ok(n),
            // The slave side closing yields EIO on Linux; treat as EOF.
            Err(nix::errno::Errno::EIO) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    /// Write bytes (e.g. keystrokes) to the shell.
    pub fn write(&self, buf: &[u8]) -> Result<usize, PtyError> {
        Ok(nix::unistd::write(self.master_borrow(), buf)?)
    }

    /// Propagate a window resize to the PTY (sends SIGWINCH to the shell).
    pub fn set_winsize(&self, rows: u16, cols: u16) -> Result<(), PtyError> {
        let ws = winsize(rows, cols);
        let ret = unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
        if ret < 0 {
            return Err(nix::errno::Errno::last().into());
        }
        Ok(())
    }

    /// Non-blocking check for child exit; returns the exit status if exited.
    pub fn try_wait(&mut self) -> Result<Option<i32>, PtyError> {
        if let Some(s) = self.status {
            return Ok(Some(s));
        }
        match waitpid(self.pid, Some(WaitPidFlag::WNOHANG))? {
            WaitStatus::Exited(_, code) => {
                self.status = Some(code);
                Ok(Some(code))
            }
            WaitStatus::Signaled(_, sig, _) => {
                let s = 128 + sig as i32;
                self.status = Some(s);
                Ok(Some(s))
            }
            _ => Ok(None),
        }
    }

    /// Block until the child exits, returning its status.
    pub fn wait(&mut self) -> Result<i32, PtyError> {
        if let Some(s) = self.status {
            return Ok(s);
        }
        let s = match waitpid(self.pid, None)? {
            WaitStatus::Exited(_, code) => code,
            WaitStatus::Signaled(_, sig, _) => 128 + sig as i32,
            _ => 0,
        };
        self.status = Some(s);
        Ok(s)
    }

    /// Terminate the child.
    pub fn kill(&self) -> Result<(), PtyError> {
        let _ = kill(self.pid, Signal::SIGHUP);
        Ok(())
    }
}

impl Drop for PtyHandle {
    fn drop(&mut self) {
        if self.status.is_none() {
            let _ = self.kill();
            let _ = waitpid(self.pid, Some(WaitPidFlag::WNOHANG));
        }
    }
}

/// Resolve the command/argv/env/cwd/uid for a request, then fork+exec under a
/// fresh PTY. The `pre_exec` closure runs in the child after `setsid` and PTY
/// setup but before `execvpe` — the privilege drop and PAM credentials hook in
/// here.
pub(crate) fn spawn_with(
    req: &SpawnRequest,
    pre_exec: impl FnOnce() -> Result<(), nix::errno::Errno>,
) -> Result<PtyHandle, PtyError> {
    use nix::unistd::User;

    // Resolve the target user (defaults to current).
    let target = match &req.user {
        Some(name) => User::from_name(name)?.ok_or_else(|| PtyError::UnknownUser(name.clone()))?,
        None => {
            let uid = nix::unistd::getuid();
            User::from_uid(uid)?.ok_or_else(|| PtyError::UnknownUser(uid.to_string()))?
        }
    };

    // Build the program, argv, and env *before* fork (no allocation in child).
    let shell =
        std::env::var("SHELL").unwrap_or_else(|_| target.shell.to_string_lossy().into_owned());
    let (program, argv) = match &req.command {
        Some(cmd) if !cmd.is_empty() => {
            let prog = resolve_program(&cmd[0])?;
            let argv = cmd.iter().map(|s| cstr(s)).collect::<Result<Vec<_>, _>>()?;
            (prog, argv)
        }
        _ => {
            let prog = resolve_program(&shell)?;
            // Login shell convention: argv[0] = "-<basename>".
            let base = shell.rsplit('/').next().unwrap_or("sh");
            let argv0 = cstr(&format!("-{base}"))?;
            (prog, vec![argv0])
        }
    };

    let mut env_map: std::collections::BTreeMap<String, String> = std::env::vars().collect();
    env_map.insert("TERM".to_string(), req.term.clone());
    env_map.insert(
        "HOME".to_string(),
        target.dir.to_string_lossy().into_owned(),
    );
    env_map.insert("USER".to_string(), target.name.clone());
    env_map.insert("SHELL".to_string(), shell.clone());
    for (k, v) in &req.env {
        env_map.insert(k.clone(), v.clone());
    }
    let envp = env_map
        .iter()
        .map(|(k, v)| cstr(&format!("{k}={v}")))
        .collect::<Result<Vec<_>, _>>()?;

    let ws = winsize(req.rows, req.cols);
    let pty = openpty(Some(&ws), None)?;
    let master = pty.master;
    let slave = pty.slave;
    let slave_raw = slave.as_raw_fd();
    let master_raw = master.as_raw_fd();

    match unsafe { nix::unistd::fork()? } {
        ForkResult::Child => {
            // Child: only async-signal-safe libc calls from here on.
            unsafe {
                if libc::setsid() < 0 {
                    libc::_exit(126);
                }
                // Acquire the controlling terminal.
                if libc::ioctl(slave_raw, libc::TIOCSCTTY as _, 0) < 0 {
                    libc::_exit(126);
                }
                // Wire stdio to the slave.
                libc::dup2(slave_raw, 0);
                libc::dup2(slave_raw, 1);
                libc::dup2(slave_raw, 2);
                if slave_raw > 2 {
                    libc::close(slave_raw);
                }
                libc::close(master_raw);
            }
            // Privilege drop / PAM credential hook.
            if pre_exec().is_err() {
                unsafe { libc::_exit(125) };
            }
            // Exec; only returns on failure.
            let _ = nix::unistd::execve(&program, &argv, &envp);
            unsafe { libc::_exit(127) };
        }
        ForkResult::Parent { child } => {
            drop(slave); // parent doesn't need the slave end
            Ok(PtyHandle {
                master,
                pid: child,
                status: None,
            })
        }
    }
}

fn cstr(s: &str) -> Result<CString, PtyError> {
    CString::new(s).map_err(|_| PtyError::BadCString)
}

/// Resolve a program name to an absolute path (searching `PATH` if needed),
/// so the cross-platform `execve` can be used. Runs before fork.
fn resolve_program(prog: &str) -> Result<CString, PtyError> {
    if prog.contains('/') {
        return cstr(prog);
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            let cand = format!("{dir}/{prog}");
            if std::path::Path::new(&cand).exists() {
                return cstr(&cand);
            }
        }
    }
    cstr(prog) // let execve fail -> _exit(127) if not found
}

/// Drop privileges to `user`: setgid, initgroups, then setuid (in that order).
/// Only meaningful when running as root. Linux-only (uses `initgroups`).
#[cfg(target_os = "linux")]
pub(crate) fn drop_privileges(name: &str) -> Result<(), nix::errno::Errno> {
    use nix::unistd::{User, initgroups, setgid, setuid};
    let user = match User::from_name(name) {
        Ok(Some(u)) => u,
        _ => return Err(nix::errno::Errno::ENOENT),
    };
    let cname = CString::new(name).map_err(|_| nix::errno::Errno::EINVAL)?;
    setgid(user.gid)?;
    initgroups(&cname, user.gid)?;
    setuid(user.uid)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read until the child exits, accumulating all PTY output.
    fn read_to_end(h: &mut PtyHandle) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match h.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
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
        // `stty size` prints "<rows> <cols>" from the controlling tty.
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
        // Sleep briefly, then report size — gives us time to resize.
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
